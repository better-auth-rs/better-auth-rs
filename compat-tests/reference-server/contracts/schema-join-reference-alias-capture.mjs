import { writeFileSync } from "node:fs";
import { captureSchemaJoinReferences } from "./schema-join-reference-capture.mjs";

const serialized = `${JSON.stringify(await captureSchemaJoinReferences({ aliases: true }), null, 2)}\n`;
if (process.argv[2]) writeFileSync(process.argv[2], serialized);
else process.stdout.write(serialized);
