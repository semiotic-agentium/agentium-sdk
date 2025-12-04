import { AgentiumClient } from './index';
import axios from 'axios';
import MockAdapter from 'axios-mock-adapter';

describe('AgentiumClient', () => {
  let mock: MockAdapter;

  beforeAll(() => {
    mock = new MockAdapter(axios);
  });

  afterEach(() => {
    mock.reset();
  });

  afterAll(() => {
    mock.restore();
  });

  it('should be defined', () => {
    expect(AgentiumClient).toBeDefined();
  });

  it('should have a connectGoogleIdentity method', () => {
    const client = new AgentiumClient();
    expect(client.connectGoogleIdentity).toBeInstanceOf(Function);
  });

  // Test should no longer expect 'Not Implemented' after actual implementation
  // Keeping this for now as a placeholder, but it will be removed or updated soon.
  it('connectGoogleIdentity should return a Promise (initial state)', async () => {
    const client = new AgentiumClient();
    // Expect a rejected promise due to unmocked API call, not 'Not Implemented'
    // This test will be removed once actual API calls are mocked properly for all tests.
    const promise = client.connectGoogleIdentity('some-token');
    expect(promise).toBeInstanceOf(Promise);
    // We expect it to fail if not mocked, but no specific message needed here, just that it's a promise.
    // We'll rely on the more specific API call tests for actual behavior.
    await expect(promise).rejects.not.toBeUndefined(); // Expect some rejection, not specific text
  });

  it('should accept a baseURL in the constructor and use default if not provided', () => {
    // Mock axios.create to inspect the baseURL passed
    const axiosCreateSpy = vi.spyOn(axios, 'create');
    
    const defaultClient = new AgentiumClient();
    expect(axiosCreateSpy).toHaveBeenCalledWith({
      baseURL: 'https://api.agentium.network',
    });
    axiosCreateSpy.mockClear();

    const customURL = 'http://localhost:3000';
    const customClient = new AgentiumClient({ baseURL: customURL });
    expect(axiosCreateSpy).toHaveBeenCalledWith({
      baseURL: customURL,
    });
    axiosCreateSpy.mockRestore();
  });

  it('should make a POST request to the default /v1/identity/connect endpoint', async () => {
    const client = new AgentiumClient();
    const googleToken = 'test-google-jwt';
    const expectedResponse = { privy_user_id: '123', did: 'did:eth:abc', badge: true };

    mock.onPost('https://api.agentium.network/v1/identity/connect', { id_token: googleToken })
        .reply(200, expectedResponse);

    const response = await client.connectGoogleIdentity(googleToken);
    expect(response).toEqual(expectedResponse);
  });

  it('should make a POST request to the custom /v1/identity/connect endpoint', async () => {
    const customBaseURL = 'http://localhost:8080';
    const client = new AgentiumClient({ baseURL: customBaseURL });
    const googleToken = 'test-custom-google-jwt';
    const expectedResponse = { privy_user_id: '456', did: 'did:eth:def', badge: false };

    mock.onPost(`${customBaseURL}/v1/identity/connect`, { id_token: googleToken })
        .reply(200, expectedResponse);

    const response = await client.connectGoogleIdentity(googleToken);
    expect(response).toEqual(expectedResponse);
  });

  it('should handle API errors gracefully', async () => {
    const client = new AgentiumClient();
    const googleToken = 'invalid-token';
    const errorMessage = 'Request failed with status code 400';

    mock.onPost('https://api.agentium.network/v1/identity/connect', { id_token: googleToken })
        .reply(400, { message: 'Bad Request' }); // Mock a 400 error

    await expect(client.connectGoogleIdentity(googleToken)).rejects.toThrow(errorMessage);
  });
});
