'use client';

import { useEffect, useId, useRef, useState } from 'react';
import { useTheme } from 'next-themes';

export function Mermaid({ chart }: { chart: string }) {
  const id = useId();
  const [svg, setSvg] = useState('');
  const containerRef = useRef<HTMLDivElement>(null);
  const currentChartRef = useRef<string>(null);
  const currentThemeRef = useRef<string | undefined>(undefined);
  const { resolvedTheme } = useTheme();

  useEffect(() => {
    if (
      currentChartRef.current === chart &&
      currentThemeRef.current === resolvedTheme
    ) return;
    if (!containerRef.current) return;
    const container = containerRef.current;
    currentChartRef.current = chart;
    currentThemeRef.current = resolvedTheme;

    async function renderChart() {
      const { default: mermaid } = await import('mermaid');

      try {
        mermaid.initialize({
          startOnLoad: false,
          securityLevel: 'loose',
          fontFamily: 'inherit',
          themeCSS: 'margin: 1.5rem auto 0;',
          theme: resolvedTheme === 'dark' ? 'dark' : 'default',
        });

        const { svg, bindFunctions } = await mermaid.render(
          id,
          chart.replaceAll('\\n', '\n'),
        );

        bindFunctions?.(container);
        setSvg(svg);
      } catch (error) {
        console.error('Error while rendering mermaid', error);
      }
    }

    renderChart();
  }, [chart, id, resolvedTheme]);

  return (
    <div
      ref={containerRef}
      // biome-ignore lint: svg from mermaid
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  );
}
