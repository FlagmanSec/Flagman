// How wide a short label is on screen, so a chart can leave enough room for
// its axis labels ("150 kB" is short, "150 كيلوبايت" is not).

let context: CanvasRenderingContext2D | null | undefined;

export function textWidth(text: string, fontPx = 11): number {
  if (context === undefined) context = document.createElement('canvas').getContext('2d');
  if (!context) return text.length * fontPx * 0.6;
  context.font = `${fontPx}px ${getComputedStyle(document.body).fontFamily}`;
  return context.measureText(text).width;
}
