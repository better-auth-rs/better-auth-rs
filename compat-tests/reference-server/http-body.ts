export function httpBodyOptions(profile: string) {
  if (profile === "http-body-csrf-explicit") {
    return { advanced: { disableOriginCheck: true, disableCSRFCheck: false } };
  }
  if (profile === "http-body-csrf-legacy") {
    return { advanced: { disableOriginCheck: true } };
  }
  return {};
}
