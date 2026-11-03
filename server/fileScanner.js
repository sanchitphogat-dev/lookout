"use strict";

const service = require("./services/fileScanner");

const IMAGE_SIGNATURES = {
  png: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
  jpg: [0xFF, 0xD8, 0xFF],
  jpeg: [0xFF, 0xD8, 0xFF],
  gif: [0x47, 0x49, 0x46, 0x38],
  webp: [0x52, 0x49, 0x46, 0x46] // Followed by 'WEBP' at offset 8
};

function isValidImageHeader(buffer, ext) {
  if (!buffer || !ext) return false;
  const cleanExt = ext.replace('.', '').toLowerCase();
  const signature = IMAGE_SIGNATURES[cleanExt];
  if (!signature) return false;
  if (buffer.length < signature.length) return false;

  for (let i = 0; i < signature.length; i++) {
    if (buffer[i] !== signature[i]) return false;
  }
  if (cleanExt === 'webp' && buffer.length >= 12) {
    if (
      buffer[8] !== 0x57 ||
      buffer[9] !== 0x45 ||
      buffer[10] !== 0x42 ||
      buffer[11] !== 0x50
    ) {
      return false;
    }
  }
  return true;
}

module.exports = {
  ...service,
  IMAGE_SIGNATURES,
  isValidImageHeader,
};
