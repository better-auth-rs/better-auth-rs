import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: (
        <>
          <svg
            width={24}
            height={24}
            viewBox="0 0 200 200"
            xmlns="http://www.w3.org/2000/svg"
            xmlnsXlink="http://www.w3.org/1999/xlink"
            fill="currentColor"
            stroke="currentColor"
          >
            <g transform="translate(100, 100)">
              <g transform="translate(-40, -40) scale(0.16)">
                <rect x="69" y="121" width="86.9879" height="259" />
                <rect x="337.575" y="121" width="92.4247" height="259" />
                <rect x="427.282" y="121" width="83.4555" height="174.52" transform="rotate(90 427.282 121)" />
                <rect x="430" y="296.544" width="83.4555" height="177.238" transform="rotate(90 430 296.544)" />
                <rect x="252.762" y="204.455" width="92.0888" height="96.7741" transform="rotate(90 252.762 204.455)" />
              </g>
              <g mask="url(#nav-logo-holes)">
                <circle r="80" fill="none" strokeWidth="16" />
                <g>
                  {Array.from({ length: 32 }, (_, i) => (
                    <polygon key={i} strokeWidth="5" strokeLinejoin="round" points="86,5.5 95,0 86,-5.5" transform={`rotate(${i * 11.25})`} />
                  ))}
                </g>
                <g>
                  {[45, 135, 225, 315].map((r) => (
                    <polygon key={r} strokeWidth="10" strokeLinejoin="round" points="-13,-78 0,-65 13,-78" transform={`rotate(${r})`} />
                  ))}
                </g>
              </g>
              <g>
                {[[45,-45],[45,45],[-45,45],[-45,-45]].map(([cx,cy]) => (
                  <circle key={`${cx},${cy}`} cx={cx} cy={cy} r="5" />
                ))}
              </g>
              <mask id="nav-logo-holes">
                <rect x="-110" y="-110" width="220" height="220" fill="white" />
                {[[53,-53],[53,53],[-53,53],[-53,-53]].map(([cx,cy]) => (
                  <circle key={`${cx},${cy}`} cx={cx} cy={cy} r="5.5" fill="black" />
                ))}
              </mask>
            </g>
          </svg>
          <span>Better Auth <span style={{ opacity: 0.5 }}>in Rust</span></span>
        </>
      ),
    },
  };
}
