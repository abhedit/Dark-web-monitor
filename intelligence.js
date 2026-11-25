// Values are safe metadata labels shared by adapters, reports and the console.
export const guidance = {
  'Unclassified exposure': 'Identify the affected business owner and corroborate the report with the provider.',
  'Identity exposure': 'Review affected identities with the identity team and check recent account activity.',
  'Session exposure': 'Review sign-in activity and revoke affected sessions through the identity provider.',
  'Secret exposure': 'Identify the application owner, rotate affected secrets and review access logs.',
  'Infostealer exposure': 'Ask endpoint responders to assess affected devices and review linked identities.',
  'Brand mention': 'Ask the brand owner to assess the reference and document the business impact.',
  'Ransomware claim': 'Escalate to incident response and corroborate the claim against internal evidence.'
};
export const channels = ['Unspecified','Breach database','Forum','Messaging channel','Leak site','Paste site','Marketplace'];
export function classify(category,channel){
  if(!Object.hasOwn(guidance,category)||!channels.includes(channel)){
    throw Object.assign(Error('Unsupported exposure category or source channel'),{status:400});
  }
}
