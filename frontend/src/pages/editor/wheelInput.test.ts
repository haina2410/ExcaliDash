import { describe, expect, it } from "vitest";
import { isDiscreteMouseWheel } from "./wheelInput";

const input = (
  overrides: Partial<Parameters<typeof isDiscreteMouseWheel>[0]> = {},
) => ({
  deltaMode: 0,
  deltaX: 0,
  deltaY: 0,
  ...overrides,
});

describe("isDiscreteMouseWheel", () => {
  it("recognizes line and page deltas as a mouse wheel", () => {
    expect(isDiscreteMouseWheel(input({ deltaMode: 1, deltaY: 3 }))).toBe(true);
    expect(isDiscreteMouseWheel(input({ deltaMode: 2, deltaY: 1 }))).toBe(true);
  });

  it("recognizes legacy and common pixel mouse-wheel steps", () => {
    expect(
      isDiscreteMouseWheel(input({ deltaY: 100, wheelDeltaY: -120 })),
    ).toBe(true);
    expect(isDiscreteMouseWheel(input({ deltaY: -100 }))).toBe(true);
  });

  it("leaves smooth vertical trackpad scrolling available for panning", () => {
    expect(isDiscreteMouseWheel(input({ deltaY: 2.5, wheelDeltaY: -3 }))).toBe(
      false,
    );
    expect(isDiscreteMouseWheel(input({ deltaY: 24 }))).toBe(false);
  });

  it("leaves horizontal and diagonal trackpad scrolling available for panning", () => {
    expect(isDiscreteMouseWheel(input({ deltaX: 20, deltaY: 0 }))).toBe(false);
    expect(isDiscreteMouseWheel(input({ deltaX: 8, deltaY: 100 }))).toBe(false);
  });
});
