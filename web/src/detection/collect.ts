// Browser sampling adapted from yacuo/check-cc (MIT). Scoring was removed;
// collection is explicit, local and uses a bounded font list. See THIRD_PARTY_NOTICES.md.
export interface BrowserSnapshot {
  timezone: string;
  offset_minutes: number;
  locale: string;
  languages: string[];
  user_agent: string;
  platform: string;
  fonts: string[] | null;
}

export const fontCandidates = [
  "PingFang SC",
  "PingFang TC",
  "Microsoft YaHei",
  "SimSun",
  "Noto Sans CJK SC",
  "Arial",
  "Helvetica",
  "Segoe UI",
] as const;

export function hasFont(font: string): boolean {
  const context = document.createElement("canvas").getContext("2d");
  if (!context) return false;
  const text = "中文字体 ABCabc012";
  return ["monospace", "sans-serif", "serif"].some((base) => {
    context.font = `72px ${base}`;
    const baseline = context.measureText(text).width;
    context.font = `72px "${font}", ${base}`;
    return Math.abs(context.measureText(text).width - baseline) > 0.5;
  });
}

export function collectBrowser(includeFonts: boolean): BrowserSnapshot {
  const resolved = Intl.DateTimeFormat().resolvedOptions();
  return {
    timezone: resolved.timeZone ?? "",
    offset_minutes: -new Date().getTimezoneOffset(),
    locale: resolved.locale,
    languages: [...navigator.languages].slice(0, 20),
    user_agent: navigator.userAgent.slice(0, 512),
    platform: navigator.platform.slice(0, 100),
    fonts: includeFonts ? fontCandidates.filter(hasFont) : null,
  };
}
