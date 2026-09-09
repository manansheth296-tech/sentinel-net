import { mockResult } from "../data/mockResult.js";

/**
 * POST /api/analyze with a file upload.
 * Falls back to mock data if USE_MOCK env var is set or backend is unreachable.
 */
export async function analyzeFile(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch("/api/analyze", {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Server error ${response.status}: ${text}`);
  }

  return response.json();
}

/**
 * Returns the static mock result instantly — used by the "Load sample" button.
 */
export async function loadMock() {
  return new Promise((resolve) =>
    setTimeout(() => resolve(mockResult), 800)
  );
}
