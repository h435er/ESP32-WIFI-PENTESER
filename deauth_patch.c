/*
 * deauth_patch.c
 * Linker-wrap that disables the ESP-IDF raw frame sanity check,
 * enabling esp_wifi_80211_tx() to inject 802.11 deauth frames.
 *
 * Referenced by build_opt.h:
 *   -Wl,--wrap=ieee80211_raw_frame_sanity_check
 */
int __wrap_ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3){
    return 0;
}
