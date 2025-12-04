interface AgentiumClientOptions {
  baseURL?: string;
}

export class AgentiumClient {
  private baseURL: string;

  constructor(options: AgentiumClientOptions = {}) {
    this.baseURL = options.baseURL || 'https://api.agentium.network';
  }

  async connectGoogleIdentity(googleToken: string): Promise<any> {
    // Minimal implementation to make the test pass
    // The actual API call with axios will be implemented in the next step
    return Promise.reject(new Error('Not Implemented'));
  }
}
