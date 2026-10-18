/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2026 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#ifdef HAVE_MUSIG2_PRENONCES

#include <stdint.h>
#include <string.h>

/* SDK headers */
#include "buffer.h"
#include "write.h"

/* Local headers */
#include "dispatcher.h"
#include "error_codes.h"
#include "handlers.h"
#include "prenonce_storage.h"
#include "sw.h"

void handler_advance_musig2_prenonces(dispatcher_context_t *dc, uint8_t protocol_version) {
    UNUSED(protocol_version);

    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    uint32_t new_hwm;
    if (!buffer_read_u32(&dc->read_buffer, &new_hwm, BE)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    prenonce_state_t state;
    if (prenonce_storage_load(&state) != PRENONCE_STORAGE_OK) {
        PRINTF("No pre-nonce state to advance\n");
        SEND_SW_EC(dc, SW_BAD_STATE, EC_ADVANCE_MUSIG2_PRENONCES_STATE_UNAVAILABLE);
        return;
    }

    uint32_t old_hwm = state.window.hwm;
    prenonce_window_advance(&state.window, new_hwm);
    uint32_t hwm = state.window.hwm;

    // a lower or equal new_hwm changes nothing, so it is not written
    bool ok = hwm == old_hwm || prenonce_storage_store(&state);
    explicit_bzero(&state, sizeof(state));
    if (!ok) {
        PRINTF("Failed to store the pre-nonce state\n");
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    uint8_t response[4];
    write_u32_be(response, 0, hwm);
    SEND_RESPONSE(dc, response, sizeof(response), SW_OK);
}

#endif  // HAVE_MUSIG2_PRENONCES
