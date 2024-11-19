/*
 ============================================================================
 Name        : hev-jni.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2021 hev
 Description : JNI
 ============================================================================
 */

#if defined(ANDROID)
#include <jni.h>
#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include "hev-jni.h"
#include "hev-main.h"

/* clang-format off */
#ifndef PKGNAME
#define PKGNAME hev/htproxy
#endif
#ifndef CLSNAME
#define CLSNAME TProxyService
#endif
/* clang-format on */

#define STR(s) STR_ARG (s)
#define STR_ARG(c) #c
#define N_ELEMENTS(arr) (sizeof (arr) / sizeof ((arr)[0]))

static JavaVM *java_vm;
static pthread_t work_thread;
static pthread_mutex_t mutex;
static pthread_key_t current_jni_env;

static void native_start_service (JNIEnv *env, jobject thiz,
                                  jstring conig_path);
static void native_stop_service (JNIEnv *env, jobject thiz);

static JNINativeMethod native_methods[] = {
    { "TProxyStartService", "(Ljava/lang/String;)V",
      (void *)native_start_service },
    { "TProxyStopService", "()V", (void *)native_stop_service },
};

static void
detach_current_thread (void *env)
{
    (*java_vm)->DetachCurrentThread (java_vm);
}

jint
JNI_OnLoad (JavaVM *vm, void *reserved)
{
    JNIEnv *env = NULL;
    jclass klass;

    java_vm = vm;
    if (JNI_OK != (*vm)->GetEnv (vm, (void **)&env, JNI_VERSION_1_4)) {
        return 0;
    }

    klass = (*env)->FindClass (env, STR (PKGNAME) "/" STR (CLSNAME));
    (*env)->RegisterNatives (env, klass, native_methods,
                             N_ELEMENTS (native_methods));
    (*env)->DeleteLocalRef (env, klass);

    pthread_key_create (&current_jni_env, detach_current_thread);
    pthread_mutex_init (&mutex, NULL);

    return JNI_VERSION_1_4;
}

static void *
thread_handler (void *data)
{
    char **argv = data;

    argv[0] = "hev-socks5-client";

    main (2, argv);

    free (argv[1]);
    free (argv);

    return NULL;
}

static void
native_start_service (JNIEnv *env, jobject thiz, jstring config_path)
{
    char **argv;
    const jbyte *bytes;

    pthread_mutex_lock (&mutex);
    if (work_thread)
        goto exit;

    argv = malloc (sizeof (char *) * 2);
    bytes = (const jbyte *)(*env)->GetStringUTFChars (env, config_path, NULL);
    argv[1] = strdup ((const char *)bytes);
    (*env)->ReleaseStringUTFChars (env, config_path, (const char *)bytes);

    pthread_create (&work_thread, NULL, thread_handler, argv);
exit:
    pthread_mutex_unlock (&mutex);
}

static void
native_stop_service (JNIEnv *env, jobject thiz)
{
    pthread_mutex_lock (&mutex);
    if (!work_thread)
        goto exit;

    quit ();
    pthread_join (work_thread, NULL);
    work_thread = 0;
exit:
    pthread_mutex_unlock (&mutex);
}

#endif
