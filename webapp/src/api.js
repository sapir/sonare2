export class ApiError extends Error {
  constructor(message, html) {
    super(message);
    this.name = "ApiError";
    this.html = html;
  }
}

export async function doApiQuery(url, ...fetchArgs) {
  const response = await fetch(`/api/${url}`, ...fetchArgs);

  if (!response.ok) {
    const text = await response.text();
    throw new ApiError(response.statusText, text);
  }

  const data = await response.json();
  return data;
}
