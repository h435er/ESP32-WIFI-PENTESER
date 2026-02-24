/*
 * deauth_patch.c
 *
 * Muss im SELBEN Ordner wie sketch_feb19d.ino liegen.
 * Überschreibt ieee80211_raw_frame_sanity_check damit der
 * ESP32-Treiber alle Frame-Typen (inkl. 0xC0 Deauth) durchlässt.
 *
 * build_opt.h muss enthalten:
 *   -Wl,--wrap=ieee80211_raw_frame_sanity_check
 */

#include <stdint.h>

int __real_ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3);

int __wrap_ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    return 0;
}
