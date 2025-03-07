import { test, flow, rejects, modules, variant } from '../runner.js'

for (const module of modules(import.meta.url)) {
  if (
    module.variant?.response_type?.includes('id_token') === true ||
    variant.response_type?.includes('id_token') === true
  ) {
    test.serial(rejects(flow()), module, { code: 'OAUTH_KEY_SELECTION_FAILED' })
  } else {
    test.serial(flow(), module)
  }
}
