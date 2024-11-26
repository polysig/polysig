// @ts-check
import { test, expect } from '@playwright/test';

import {
  server,
  parameters,
  cggmp,
  URL,
  proxyConsoleError,
} from '../../../helpers/protocols.mjs';

import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const partyKeys = require('./ecdsa.json');
const { message, dkgSessionIdSeed, signSessionIdSeed } = cggmp;

test("CGGMP: dkg and sign message", async ({ context, page }) => {
  // The default timeout is 90 seconds which fails on Firefox
  // (Chromium and Webkit are ok) so we increase the timeout here.
  //
  // SEE: https://playwright.dev/docs/test-timeouts#test-timeout
  //
  // Firefox can be up to 5x slower, here is an example
  // from a successful test run:
  //
  // Slow test file: [firefox] › cggmp.spec.js (10.6m)
  // Slow test file: [webkit] › cggmp.spec.js (2.3m)
  // Slow test file: [chromium] › cggmp.spec.js (1.2m)
  //
  test.setTimeout(60 * 1000 * 15);
  
  // DKG
  console.log("CGGMP, begin dkg...");
  let pages = [];
  let selectors = [];

  for (let i = 0;i < parameters.parties;i++) {
    const pageData = {
      partyIndex: i,
      server,
      parameters,
      sessionIdSeed: dkgSessionIdSeed,
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

  console.log("CGGMP, dkg complete, begin signing...");
  
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
    const pageData = {
      partyIndex,
      indices,
      server,
      parameters,
      sessionIdSeed: signSessionIdSeed,
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
  console.log("CGGMP, signing complete, done.");

});
