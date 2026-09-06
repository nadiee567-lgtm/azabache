// photo.js — strip ALL metadata from an image before it ever leaves the device.
//
// Re-encoding an image through a <canvas> keeps only the raw pixels: EXIF, GPS
// coordinates, camera model, timestamps and every other tag are dropped, because
// the canvas simply has nowhere to carry them. The exported image is clean —
// "no rastro". It's also capped in size so it fits through the data channel.

(function (root) {
  async function stripImage(file, maxDim = 1600, quality = 0.85) {
    const bitmap = await createImageBitmap(file);   // decodes pixels only
    let w = bitmap.width, h = bitmap.height;
    if (Math.max(w, h) > maxDim) {
      const s = maxDim / Math.max(w, h);
      w = Math.round(w * s); h = Math.round(h * s);
    }
    const canvas = document.createElement('canvas');
    canvas.width = w; canvas.height = h;
    canvas.getContext('2d').drawImage(bitmap, 0, 0, w, h);
    if (bitmap.close) bitmap.close();
    // toBlob re-encodes from the canvas → output carries zero metadata
    return await new Promise((res) => canvas.toBlob(res, 'image/jpeg', quality));
  }
  root.Photo = { stripImage };
})(typeof globalThis !== 'undefined' ? globalThis : this);
