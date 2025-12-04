// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

import { AgentiumClient, AgentiumApiError } from './index';
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

  it('should accept a baseURL in the constructor and use default if not provided', () => {
    const axiosCreateSpy = vi.spyOn(axios, 'create');

    new AgentiumClient(); // Just instantiate, no need to assign
    expect(axiosCreateSpy).toHaveBeenCalledWith({
      baseURL: 'https://api.agentium.network',
    });
    axiosCreateSpy.mockClear();

    const customURL = 'http://localhost:3000';
    new AgentiumClient({ baseURL: customURL }); // Just instantiate, no need to assign
    expect(axiosCreateSpy).toHaveBeenCalledWith({
      baseURL: customURL,
    });
    axiosCreateSpy.mockRestore();
  });

  it('should make a POST request to the default /v1/identity/connect endpoint', async () => {
    const client = new AgentiumClient();
    const googleToken = 'test-google-jwt';
    const expectedResponse = {
      privy_user_id: '123',
      did: 'did:eth:abc',
      badge: { status: 'active' },
    };

    mock
      .onPost('https://api.agentium.network/v1/identity/connect', { id_token: googleToken })
      .reply(200, expectedResponse);

    const response = await client.connectGoogleIdentity(googleToken);
    expect(response).toEqual(expectedResponse);
  });

  it('should make a POST request to the custom /v1/identity/connect endpoint', async () => {
    const customBaseURL = 'http://localhost:8080';
    const client = new AgentiumClient({ baseURL: customBaseURL });
    const googleToken = 'test-custom-google-jwt';
    const expectedResponse = {
      privy_user_id: '456',
      did: 'did:eth:def',
      badge: { status: 'inactive' },
    };

    mock
      .onPost(`${customBaseURL}/v1/identity/connect`, { id_token: googleToken })
      .reply(200, expectedResponse);

    const response = await client.connectGoogleIdentity(googleToken);
    expect(response).toEqual(expectedResponse);
  });

  it('should handle API errors gracefully with a custom error', async () => {
    const client = new AgentiumClient();
    const googleToken = 'invalid-token';

    mock
      .onPost('https://api.agentium.network/v1/identity/connect', { id_token: googleToken })
      .reply(400, { message: 'Bad Request' });

    await expect(client.connectGoogleIdentity(googleToken)).rejects.toThrow(AgentiumApiError);
    await expect(client.connectGoogleIdentity(googleToken)).rejects.toMatchObject({
      name: 'AgentiumApiError',
      statusCode: 400,
      message: 'Request failed with status code 400',
    });
  });
});
