/**
 * Tests for @pdfsmaller/pdf-decrypt
 * Roundtrip tests: encrypt with @pdfsmaller/pdf-encrypt → decrypt → verify
 * Run: npm test (after npm run build)
 */

const { decryptPDF, isEncrypted } = require('./dist/index.js');
const { encryptPDF } = require('@pdfsmaller/pdf-encrypt');
const { PDFDocument } = require('pdf-lib');

function assert(condition, message) {
  if (!condition) throw new Error('Assertion failed: ' + message);
}

async function createTestPDF(text = 'Hello, this is a test PDF!') {
  const doc = await PDFDocument.create();
  const page = doc.addPage();
  page.drawText(text, { x: 50, y: 500, size: 16 });
  return await doc.save();
}

async function createTestPDFWithMetadata(title, author) {
  const doc = await PDFDocument.create();
  doc.setTitle(title);
  doc.setAuthor(author);
  const page = doc.addPage();
  page.drawText('Metadata test document', { x: 50, y: 500, size: 16 });
  return await doc.save();
}

async function runTests() {
  console.log('Testing @pdfsmaller/pdf-decrypt...\n');
  let passed = 0;
  let failed = 0;

  // Test 1: Import check
  try {
    console.log('Test 1: Import check');
    assert(typeof decryptPDF === 'function', 'decryptPDF should be a function');
    assert(typeof isEncrypted === 'function', 'isEncrypted should be a function');
    console.log('  decryptPDF:', typeof decryptPDF);
    console.log('  isEncrypted:', typeof isEncrypted);
    console.log('  PASSED\n');
    passed++;
  } catch (e) {
    console.log('  FAILED:', e.message, '\n');
    failed++;
  }

  // Test 2: isEncrypted on plain PDF
  try {
    console.log('Test 2: isEncrypted on plain PDF');
    const pdfBytes = await createTestPDF();
    const info = await isEncrypted(new Uint8Array(pdfBytes));
    console.log('  Result:', JSON.stringify(info));
    assert(info.encrypted === false, 'Plain PDF should not be encrypted');
    console.log('  PASSED\n');
    passed++;
  } catch (e) {
    console.log('  FAILED:', e.message, '\n');
    failed++;
  }

  // Test 3: AES-256 encrypt → decrypt → verify page count
  try {
    console.log('Test 3: AES-256 roundtrip (encrypt → decrypt → verify)');
    const pdfBytes = await createTestPDF('AES-256 roundtrip test');
    const encrypted = await encryptPDF(new Uint8Array(pdfBytes), 'test123');
    console.log('  Original:', pdfBytes.length, '-> Encrypted:', encrypted.length);

    const decrypted = await decryptPDF(new Uint8Array(encrypted), 'test123');
    console.log('  Decrypted:', decrypted.length);

    const doc = await PDFDocument.load(decrypted);
    assert(doc.getPageCount() === 1, 'Should have 1 page');
    console.log('  Pages:', doc.getPageCount());
    console.log('  PASSED\n');
    passed++;
  } catch (e) {
    console.log('  FAILED:', e.message, '\n');
    failed++;
  }

  // Test 4: RC4 encrypt → decrypt → verify page count
  try {
    console.log('Test 4: RC4 roundtrip (encrypt → decrypt → verify)');
    const pdfBytes = await createTestPDF('RC4 roundtrip test');
    const encrypted = await encryptPDF(new Uint8Array(pdfBytes), 'rc4pass', { algorithm: 'RC4' });
    console.log('  Original:', pdfBytes.length, '-> Encrypted:', encrypted.length);

    const decrypted = await decryptPDF(new Uint8Array(encrypted), 'rc4pass');
    console.log('  Decrypted:', decrypted.length);

    const doc = await PDFDocument.load(decrypted);
    assert(doc.getPageCount() === 1, 'Should have 1 page');
    console.log('  Pages:', doc.getPageCount());
    console.log('  PASSED\n');
    passed++;
  } catch (e) {
    console.log('  FAILED:', e.message, '\n');
    failed++;
  }

  // Test 5: AES-256 with owner password → decrypt with user password
  try {
    console.log('Test 5: AES-256 decrypt with user password (separate owner)');
    const pdfBytes = await createTestPDF('User password test');
    const encrypted = await encryptPDF(new Uint8Array(pdfBytes), 'user123', {
      ownerPassword: 'owner456'
    });

    const decrypted = await decryptPDF(new Uint8Array(encrypted), 'user123');
    const doc = await PDFDocument.load(decrypted);
    assert(doc.getPageCount() === 1, 'Should have 1 page');
    console.log('  Decrypted with user password: OK');
    console.log('  PASSED\n');
    passed++;
  } catch (e) {
    console.log('  FAILED:', e.message, '\n');
    failed++;
  }

  // Test 6: AES-256 with owner password → decrypt with owner password
  try {
    console.log('Test 6: AES-256 decrypt with owner password');
    const pdfBytes = await createTestPDF('Owner password test');
    const encrypted = await encryptPDF(new Uint8Array(pdfBytes), 'user123', {
      ownerPassword: 'owner456'
    });

    const decrypted = await decryptPDF(new Uint8Array(encrypted), 'owner456');
    const doc = await PDFDocument.load(decrypted);
    assert(doc.getPageCount() === 1, 'Should have 1 page');
    console.log('  Decrypted with owner password: OK');
    console.log('  PASSED\n');
    passed++;
  } catch (e) {
    console.log('  FAILED:', e.message, '\n');
    failed++;
  }

  // Test 7: Wrong password → throws "Incorrect password"
  try {
    console.log('Test 7: Wrong password — should throw');
    const pdfBytes = await createTestPDF('Wrong password test');
    const encrypted = await encryptPDF(new Uint8Array(pdfBytes), 'correct');

    try {
      await decryptPDF(new Uint8Array(encrypted), 'wrong');
      console.log('  FAILED: Should have thrown\n');
      failed++;
    } catch (e) {
      console.log('  Error (expected):', e.message);
      assert(e.message.includes('Incorrect password'), 'Should mention incorrect password');
      console.log('  PASSED\n');
      passed++;
    }
  } catch (e) {
    console.log('  FAILED:', e.message, '\n');
    failed++;
  }

  // Test 8: Unencrypted PDF → throws "not encrypted"
  try {
    console.log('Test 8: Unencrypted PDF — should throw');
    const pdfBytes = await createTestPDF('Not encrypted');

    try {
      await decryptPDF(new Uint8Array(pdfBytes), 'any');
      console.log('  FAILED: Should have thrown\n');
      failed++;
    } catch (e) {
      console.log('  Error (expected):', e.message);
      assert(e.message.includes('not encrypted'), 'Should mention not encrypted');
      console.log('  PASSED\n');
      passed++;
    }
  } catch (e) {
    console.log('  FAILED:', e.message, '\n');
    failed++;
  }

  // Test 9: isEncrypted on AES-256 PDF
  try {
    console.log('Test 9: isEncrypted on AES-256 PDF');
    const pdfBytes = await createTestPDF('isEncrypted AES test');
    const encrypted = await encryptPDF(new Uint8Array(pdfBytes), 'test');

    const info = await isEncrypted(new Uint8Array(encrypted));
    console.log('  Result:', JSON.stringify(info));
    assert(info.encrypted === true, 'Should be encrypted');
    assert(info.algorithm === 'AES-256', 'Algorithm should be AES-256');
    assert(info.version === 5, 'Version should be 5');
    assert(info.revision === 6, 'Revision should be 6');
    assert(info.keyLength === 256, 'Key length should be 256 bits');
    console.log('  PASSED\n');
    passed++;
  } catch (e) {
    console.log('  FAILED:', e.message, '\n');
    failed++;
  }

  // Test 10: isEncrypted on RC4 PDF
  try {
    console.log('Test 10: isEncrypted on RC4 PDF');
    const pdfBytes = await createTestPDF('isEncrypted RC4 test');
    const encrypted = await encryptPDF(new Uint8Array(pdfBytes), 'test', { algorithm: 'RC4' });

    const info = await isEncrypted(new Uint8Array(encrypted));
    console.log('  Result:', JSON.stringify(info));
    assert(info.encrypted === true, 'Should be encrypted');
    assert(info.algorithm === 'RC4', 'Algorithm should be RC4');
    assert(info.version === 2, 'Version should be 2');
    assert(info.revision === 3, 'Revision should be 3');
    assert(info.keyLength === 128, 'Key length should be 128 bits');
    console.log('  PASSED\n');
    passed++;
  } catch (e) {
    console.log('  FAILED:', e.message, '\n');
    failed++;
  }

  // Test 11: Re-encryption roundtrip (AES → decrypt → RC4 → decrypt)
  try {
    console.log('Test 11: Re-encryption roundtrip (AES -> decrypt -> RC4 -> decrypt)');
    const pdfBytes = await createTestPDF('Re-encryption test');

    // AES-256 encrypt
    const enc1 = await encryptPDF(new Uint8Array(pdfBytes), 'pass1');
    console.log('  AES-256 encrypted:', enc1.length, 'bytes');

    // Decrypt
    const dec1 = await decryptPDF(new Uint8Array(enc1), 'pass1');
    console.log('  Decrypted:', dec1.length, 'bytes');

    // RC4 re-encrypt
    const enc2 = await encryptPDF(new Uint8Array(dec1), 'pass2', { algorithm: 'RC4' });
    console.log('  RC4 re-encrypted:', enc2.length, 'bytes');

    // Decrypt again
    const dec2 = await decryptPDF(new Uint8Array(enc2), 'pass2');
    console.log('  Decrypted again:', dec2.length, 'bytes');

    const doc = await PDFDocument.load(dec2);
    assert(doc.getPageCount() === 1, 'Should have 1 page after double roundtrip');
    console.log('  Pages:', doc.getPageCount());
    console.log('  PASSED\n');
    passed++;
  } catch (e) {
    console.log('  FAILED:', e.message, '\n');
    failed++;
  }

  // Test 12: Metadata text verification (catches PDFString encoding bugs)
  try {
    console.log('Test 12: Metadata text verification (PDFString encoding)');
    const title = 'My Secret Document Title';
    const author = 'PDFSmaller Test Author';
    const pdfBytes = await createTestPDFWithMetadata(title, author);

    // AES-256 encrypt
    const encrypted = await encryptPDF(new Uint8Array(pdfBytes), 'meta-pass');

    // Decrypt
    const decrypted = await decryptPDF(new Uint8Array(encrypted), 'meta-pass');

    // Verify metadata strings survived the roundtrip intact
    const doc = await PDFDocument.load(decrypted);
    const recoveredTitle = doc.getTitle();
    const recoveredAuthor = doc.getAuthor();
    console.log('  Original title:', title);
    console.log('  Recovered title:', recoveredTitle);
    console.log('  Original author:', author);
    console.log('  Recovered author:', recoveredAuthor);
    assert(recoveredTitle === title, 'Title should match after decrypt');
    assert(recoveredAuthor === author, 'Author should match after decrypt');
    console.log('  PASSED\n');
    passed++;
  } catch (e) {
    console.log('  FAILED:', e.message, '\n');
    failed++;
  }

  // Summary
  console.log('='.repeat(40));
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log('='.repeat(40));

  if (failed > 0) {
    console.log('\nSome tests failed!');
    process.exit(1);
  } else {
    console.log('\nAll tests passed!');
    console.log('Ready to publish: npm publish --access public');
    console.log('Powered by PDFSmaller.com');
  }
}

runTests().catch(err => {
  console.error('Test runner error:', err);
  process.exit(1);
});
