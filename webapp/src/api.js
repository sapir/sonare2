import _ from 'lodash';


export class ApiError extends Error {
  constructor(message, html) {
    super(message);
    this.name = "ApiError";
    this.html = html;
  }
}


export async function doApiQuery(url, json, fetchArgs) {
  if (!fetchArgs)
    fetchArgs = {};

  _.merge(fetchArgs, {
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
  });

  if (json) {
    fetchArgs.method = "POST";
    fetchArgs.body = JSON.stringify(json);
  }

  const response = await fetch(`/api/${url}`, fetchArgs);

  if (!response.ok) {
    const text = await response.text();
    throw new ApiError(response.statusText, text);
  }

  const data = await response.json();
  return data;
}
