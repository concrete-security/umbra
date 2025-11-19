import nextConfig from 'eslint-config-next'

const overrides = nextConfig.map((config) => {
  if (config?.name !== 'next') {
    return config
  }

  return {
    ...config,
    rules: {
      ...config.rules,
      'react/no-unescaped-entities': 'off',
      'react-hooks/set-state-in-effect': 'off',
    },
  }
})

export default overrides
