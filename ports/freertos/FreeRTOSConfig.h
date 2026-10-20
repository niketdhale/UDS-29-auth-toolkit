#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H
/* Minimal FreeRTOSConfig.h, only used by the UDS29_FREERTOS_COMPILE_CHECK build (posix GCC port).
   Real targets bring their own config; the Uds29 OS port needs the two RECURSIVE/STATIC options below. */

#define configUSE_PREEMPTION                    1
#define configUSE_IDLE_HOOK                     0
#define configUSE_TICK_HOOK                     0
#define configTICK_RATE_HZ                      ((TickType_t)1000)
#define configCPU_CLOCK_HZ                      ((unsigned long)1000000)
#define configMAX_PRIORITIES                    5
#define configMINIMAL_STACK_SIZE                ((unsigned short)256)
#define configTOTAL_HEAP_SIZE                   ((size_t)(64 * 1024))
#define configMAX_TASK_NAME_LEN                 16
#define configUSE_16_BIT_TICKS                  0
#define configUSE_MUTEXES                       1
#define configUSE_RECURSIVE_MUTEXES             1   /* required by Uds29_Os_FreeRtos.c */
#define configSUPPORT_STATIC_ALLOCATION         1   /* required by Uds29_Os_FreeRtos.c */
#define configSUPPORT_DYNAMIC_ALLOCATION        1
#define configUSE_TIMERS                        0
#define configUSE_COUNTING_SEMAPHORES           0

#define INCLUDE_vTaskDelay                      1
#define INCLUDE_vTaskDelete                     1
#define INCLUDE_xTaskGetSchedulerState          1

#endif
