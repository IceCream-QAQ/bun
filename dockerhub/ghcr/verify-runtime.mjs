import assert from "node:assert/strict";
import zlib from "node:zlib";
import { promisify } from "node:util";

const invalid = Buffer.from("200010414141fcffff07002228f00b60f7f41f000000", "hex");
const expected = { code: "ERR_BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH", errno: -17 };
assert.equal(zlib.constants.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH, -17);
assert.throws(() => zlib.brotliDecompressSync(invalid), expected);
await assert.rejects(promisify(zlib.brotliDecompress)(invalid), expected);
const decoder = zlib.createBrotliDecompress();
const decoded = new Promise((resolve, reject) => {
  decoder.once("error", resolve);
  decoder.once("end", () => reject(new Error("invalid stream accepted")));
});
decoder.resume();
for (let i = 0; i < invalid.length; i++) decoder.write(invalid.subarray(i, i + 1));
decoder.end();
const error = await decoded;
assert.equal(error.code, expected.code);
assert.equal(error.errno, expected.errno);
decoder.destroy();
await assert.rejects(new Response(new Blob([invalid]).stream().pipeThrough(new DecompressionStream("brotli"))).arrayBuffer());
const server = Bun.serve({ port: 0, fetch: () => new Response(invalid, { headers: { "Content-Encoding": "br" } }) });
try {
  await assert.rejects(fetch(server.url).then(response => response.arrayBuffer()));
  assert.deepEqual(Buffer.from(await (await fetch(server.url, { decompress: false })).arrayBuffer()), invalid);
} finally {
  server.stop(true);
}
const valid = Buffer.from("source-built Brotli round trip");
assert.deepEqual(zlib.brotliDecompressSync(zlib.brotliCompressSync(valid)), valid);
if (process.env.EXPECT_LINUX_AMD64) {
  assert.equal(process.platform, "linux");
  assert.equal(process.arch, "x64");
}
if (process.env.EXPECT_REVISION) assert.equal(Bun.revision, process.env.EXPECT_REVISION);
assert.equal(Bun.version.split("-")[0], "1.3.14");
console.log(JSON.stringify({ version: Bun.version, revision: Bun.revision, platform: process.platform, arch: process.arch, brotli: process.versions.brotli, regression: "PASS: sync, async, byte-stream, DecompressionStream, fetch, valid roundtrip" }));
