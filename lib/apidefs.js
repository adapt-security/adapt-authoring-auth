export default {
  check: {
    get: {
      summary: 'Checks current authentication status',
      responses: {
        200: {
          description: 'User authentication data',
          content: {
            'application/json': {
              schema: {
                $schema: 'https://json-schema.org/draft/2020-12/schema',
                type: 'object',
                properties: {
                  scopes: { type: 'array', items: { type: 'string' } },
                  isSuper: { type: 'boolean' },
                  user: {
                    type: 'object',
                    properties: {
                      _id: { type: 'string' },
                      email: { type: 'string' },
                      firstName: { type: 'string' },
                      lastName: { type: 'string' },
                      roles: { type: 'array', items: { type: 'string' } }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  disavow: {
    post: {
      summary: 'De-authenticates the current user from the API',
      responses: {
        204: {
          description: ''
        }
      }
    }
  },
  generatetoken: {
    post: {
      summary: 'Creates a new authentication token',
      requestBody: {
        content: {
          'application/json': {
            schema: {
              $schema: 'https://json-schema.org/draft/2020-12/schema',
              type: 'object',
              properties: { lifespan: { type: 'string' } }
            }
          }
        }
      },
      responses: {
        200: {
          description: '',
          content: {
            'application/json': {
              schema: { properties: { token: { type: 'string' } } }
            }
          }
        }
      }
    }
  },
  tokens: {
    get: {
      summary: 'Retrieve all authentication tokens for current user',
      responses: {
        200: {
          description: '',
          content: {
            'application/json': {
              schema: {
                type: 'array',
                items: {
                  properties: {
                    userId: { type: 'string' },
                    createdAt: { type: 'string' },
                    usedAt: { type: 'string' },
                    authType: { type: 'string' }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
