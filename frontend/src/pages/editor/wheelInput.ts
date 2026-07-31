type WheelInput = Pick<WheelEvent, "deltaMode" | "deltaX" | "deltaY"> & {
  wheelDeltaY?: number;
};

const PIXEL_DELTA_MODE = 0;
const LEGACY_MOUSE_WHEEL_STEP = 120;
const COMMON_PIXEL_MOUSE_WHEEL_STEPS = new Set([100]);

/**
 * WheelEvent does not identify its hardware source. Prefer native panning unless
 * the event has the discrete step pattern emitted by a traditional mouse wheel.
 */
export const isDiscreteMouseWheel = (event: WheelInput): boolean => {
  if (event.deltaX !== 0) return false;

  if (event.deltaMode !== PIXEL_DELTA_MODE) return true;

  if (typeof event.wheelDeltaY === "number") {
    const legacyDelta = Math.abs(event.wheelDeltaY);
    return (
      legacyDelta >= LEGACY_MOUSE_WHEEL_STEP &&
      legacyDelta % LEGACY_MOUSE_WHEEL_STEP === 0
    );
  }

  return COMMON_PIXEL_MOUSE_WHEEL_STEPS.has(Math.abs(event.deltaY));
};
