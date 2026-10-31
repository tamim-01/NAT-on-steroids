export function quotaBytes(value: number) {
  if (value < 1000) return `${value} B`;
  if (value < 1e6) return `${(value / 1000).toFixed(1)} KB`;
  if (value < 1e9) return `${(value / 1e6).toFixed(1)} MB`;
  return `${(value / 1e9).toFixed(1)} GB`;
}
export function bytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MB`;
  return `${(value / 1024 ** 3).toFixed(1)} GB`;
}
