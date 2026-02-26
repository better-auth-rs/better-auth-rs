import { generateFiles } from 'fumadocs-openapi';
import { createOpenAPI } from 'fumadocs-openapi/server';

const server = createOpenAPI({
  input: ['./better-auth.json'],
});

async function main() {
  await generateFiles({
    input: server,
    output: './content/docs/reference/openapi',
    per: 'tag',
  });

  console.log('OpenAPI files generated successfully!');
}

main().catch(console.error);
