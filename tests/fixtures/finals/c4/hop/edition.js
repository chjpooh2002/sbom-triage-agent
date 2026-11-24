export const write = value => emit("fixed");
export function defer(value) {
  return later(value, () => emit(value));
}
