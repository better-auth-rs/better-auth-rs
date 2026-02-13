import Image from 'next/image';
import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: (
        <>
          <Image src="/logo.svg" alt="Better Auth RS" width={24} height={24} />
          <span>Better Auth RS</span>
        </>
      ),
    },
  };
}
