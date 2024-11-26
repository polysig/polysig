// @ts-check
import { test, expect } from '@playwright/test';

import {
  server,
  parameters,
  frost,
  URL,
  proxyConsoleError,
} from '../../../helpers/protocols.mjs';

import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const partyKeys = require('./schnorr-serde.json');
const { message, identifiers } = frost;

test("FROST: dkg and sign message", async ({ context, page }) => {
  // DKG
  console.log("FROST Secp256k1 Taproot, begin dkg...");
  let pages = [];
  let selectors = [];

  for (let i = 0;i < parameters.parties;i++) {
    const pageData = {
      partyIndex: i,
      server,
      parameters,
      identifiers,
    };
    const url = `${URL}/dkg.html?data=${encodeURIComponent(JSON.stringify(pageData))}&keys=${encodeURIComponent(JSON.stringify(partyKeys.slice(0, parameters.parties)))}`;

    const page = await context.newPage();
    proxyConsoleError(`p${i + 1}`, page);
    await page.goto(url);
    await page.bringToFront();
    
    pages.push(page);
    selectors.push(page.waitForSelector(".key-share"));
  }

  await Promise.all(selectors);

  const keyShares = [];
  for (const page of pages) {
      const keyShare = JSON.parse(await page.textContent(".key-share"));
      keyShares.push(keyShare);
  }

  console.assert(keyShares.length === parameters.parties);

  console.log("FROST Secp256k1 Taproot, dkg complete, begin signing...");
  
  // Sign
  pages = [];
  selectors = [];

  const indices = [0, 2];
  const signers = [
    keyShares[0].keyShare,
    keyShares[2].keyShare,
  ];
  
  let index = 0;
  for (const keyShare of signers) {
    const partyIndex = indices[index];
    console.log(partyIndex);
    const pageData = {
      partyIndex,
      indices,
      server,
      parameters,
      identifiers: indices.map((i) => identifiers[i]),
      keyShare,
      message,
    };

    const url = `${URL}/sign.html?data=${encodeURIComponent(JSON.stringify(pageData))}&keys=${encodeURIComponent(JSON.stringify(partyKeys.slice(0, parameters.parties)))}`;

    const page = await context.newPage();
    proxyConsoleError(`p${index + 1}`, page);
    await page.goto(url);
    await page.bringToFront();
    
    pages.push(page);
    selectors.push(page.waitForSelector(".signature"));

    index++;

  }
  
  await Promise.all(selectors);

  const signatures = [];
  for (const page of pages) {
      const signature = JSON.parse(await page.textContent(".signature"));
      signatures.push(signature);
  }

  console.assert(signatures.length === parameters.threshold);
  console.log("FROST Secp256k1 Taproot, signing complete, done.");
});
