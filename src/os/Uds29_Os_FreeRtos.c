/* OS port for FreeRTOS. Needs configUSE_RECURSIVE_MUTEXES = 1 and configSUPPORT_STATIC_ALLOCATION = 1.
   The mutex is created on first use (inside a critical section), so no init call is required. */
#include "Uds29_Os.h"
#include "FreeRTOS.h"
#include "semphr.h"
#include "task.h"

static StaticSemaphore_t g_mtx_buf;
static SemaphoreHandle_t volatile g_mtx;

void Uds29_Os_Lock(void) {
    if (!g_mtx) {
        taskENTER_CRITICAL();
        if (!g_mtx) g_mtx = xSemaphoreCreateRecursiveMutexStatic(&g_mtx_buf);
        taskEXIT_CRITICAL();
    }
    (void)xSemaphoreTakeRecursive(g_mtx, portMAX_DELAY);
}

void Uds29_Os_Unlock(void) { (void)xSemaphoreGiveRecursive(g_mtx); }

uint32_t Uds29_Os_GetTimeMs(void) { return (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS); }
