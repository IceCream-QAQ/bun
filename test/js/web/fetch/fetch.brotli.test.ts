import { expect, test } from "bun:test";

import brotliFile from "./fetch.brotli.test.ts.br" with { type: "file" };
import gzipFile from "./fetch.brotli.test.ts.gzip" with { type: "file" };

test("fetch brotli response works", async () => {
  const brotli = await Bun.file(brotliFile).arrayBuffer();
  const gzip = await Bun.file(gzipFile).arrayBuffer();

  using server = Bun.serve({
    port: 0,
    fetch(req) {
      if (req.headers.get("Accept-Encoding") === "br") {
        return new Response(brotli, {
          headers: {
            "Content-Encoding": "br",
          },
        });
      }

      if (req.headers.get("Accept-Encoding") === "gzip") {
        return new Response(gzip, {
          headers: {
            "Content-Encoding": "gzip",
          },
        });
      }

      return new Response("bad!", {
        status: 400,
      });
    },
  });
  const [firstText, secondText, { headers }] = await Promise.all([
    fetch(`${server.url}/logo.svg`, {
      headers: {
        "Accept-Encoding": "br",
      },
    }).then(res => res.text()),
    fetch(`${server.url}/logo.svg`, {
      headers: {
        "Accept-Encoding": "gzip",
      },
    }).then(res => res.text()),
    fetch(`${server.url}/logo.svg`, {
      headers: {
        "Accept-Encoding": "br",
      },
      decompress: false,
    }),
  ]);

  expect(firstText).toBe(secondText);
  expect(headers.get("Content-Encoding")).toBe("br");
});

test("fetch rejects a Brotli invalid block switch (CVE-2026-111497)", async () => {
  const invalid = Buffer.from("200010414141fcffff07002228f00b60f7f41f000000", "hex");
  using server = Bun.serve({
    port: 0,
    fetch() {
      return new Response(invalid, { headers: { "Content-Encoding": "br" } });
    },
  });
  await expect(fetch(server.url).then(response => response.arrayBuffer())).rejects.toThrow();
  const raw = await fetch(server.url, { decompress: false });
  expect(Buffer.from(await raw.arrayBuffer())).toEqual(invalid);
});
