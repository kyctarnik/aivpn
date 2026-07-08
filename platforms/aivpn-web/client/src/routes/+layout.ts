export const ssr = false;
export const prerender = false;

import type { LayoutLoad } from './$types';
export const load: LayoutLoad = async () => {
  return {};
};
