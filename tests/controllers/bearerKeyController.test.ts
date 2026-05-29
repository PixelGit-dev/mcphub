import { Request, Response } from 'express';

const mockBearerKeyDao = {
  findAll: jest.fn(),
  findById: jest.fn(),
  create: jest.fn(),
  update: jest.fn(),
  delete: jest.fn(),
};

const mockLoadSettings = jest.fn();

jest.mock('../../src/dao/index.js', () => ({
  getBearerKeyDao: jest.fn(() => mockBearerKeyDao),
}));

jest.mock('../../src/config/configManager.js', () => ({
  loadSettings: mockLoadSettings,
}));

import {
  createBearerKey,
  deleteBearerKey,
  getBearerKeys,
  updateBearerKey,
} from '../../src/controllers/bearerKeyController.js';

const makeRes = () => {
  const res = {
    json: jest.fn().mockReturnThis(),
    status: jest.fn().mockReturnThis(),
  };
  return res as unknown as Response;
};

const makeReq = (overrides: Record<string, any> = {}) =>
  ({
    body: {},
    params: {},
    user: { username: 'alice', isAdmin: false },
    ...overrides,
  }) as unknown as Request;

describe('bearerKeyController', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockLoadSettings.mockResolvedValue({
      groups: [{ id: 'group-1', name: 'visible-group', servers: [] }],
      mcpServers: {
        'visible-server': { command: 'node' },
      },
    });
  });

  it('returns only the current user keys for non-admin requests', async () => {
    mockBearerKeyDao.findAll.mockResolvedValue([
      { id: 'key-1', name: 'mine', token: 'a', enabled: true, accessType: 'all', createdBy: 'alice' },
      { id: 'key-2', name: 'other', token: 'b', enabled: true, accessType: 'all', createdBy: 'bob' },
      { id: 'key-3', name: 'legacy', token: 'c', enabled: true, accessType: 'all' },
    ]);

    const req = makeReq();
    const res = makeRes();

    await getBearerKeys(req, res);

    expect(res.json).toHaveBeenCalledWith({
      success: true,
      data: [
        expect.objectContaining({
          id: 'key-1',
          createdBy: 'alice',
        }),
      ],
    });
  });

  it('returns all keys for admin requests', async () => {
    mockBearerKeyDao.findAll.mockResolvedValue([
      { id: 'key-1', name: 'mine', token: 'a', enabled: true, accessType: 'all', createdBy: 'alice' },
      { id: 'key-2', name: 'other', token: 'b', enabled: true, accessType: 'all', createdBy: 'bob' },
    ]);

    const req = makeReq({
      user: { username: 'admin', isAdmin: true },
    });
    const res = makeRes();

    await getBearerKeys(req, res);

    expect(res.json).toHaveBeenCalledWith({
      success: true,
      data: expect.arrayContaining([
        expect.objectContaining({ id: 'key-1' }),
        expect.objectContaining({ id: 'key-2' }),
      ]),
    });
  });

  it('creates a user-owned key and limits scopes to visible groups and servers', async () => {
    mockBearerKeyDao.create.mockImplementation(async (payload) => ({
      id: 'created-key',
      ...payload,
    }));

    const req = makeReq({
      body: {
        name: 'client key',
        token: 'secret-token',
        enabled: true,
        accessType: 'custom',
        allowedGroups: ['visible-group', 'hidden-group'],
        allowedServers: ['visible-server', 'hidden-server'],
      },
    });
    const res = makeRes();

    await createBearerKey(req, res);

    expect(mockBearerKeyDao.create).toHaveBeenCalledWith({
      name: 'client key',
      token: 'secret-token',
      enabled: true,
      accessType: 'custom',
      allowedGroups: ['visible-group'],
      allowedServers: ['visible-server'],
      createdBy: 'alice',
    });
    expect(res.status).toHaveBeenCalledWith(201);
  });

  it('rejects updates to another user key for non-admin requests', async () => {
    mockBearerKeyDao.findById.mockResolvedValue({
      id: 'key-2',
      name: 'other',
      token: 'token',
      enabled: true,
      accessType: 'all',
      createdBy: 'bob',
    });

    const req = makeReq({
      params: { id: 'key-2' },
      body: { name: 'renamed' },
    });
    const res = makeRes();

    await updateBearerKey(req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(mockBearerKeyDao.update).not.toHaveBeenCalled();
  });

  it('rejects deleting another user key for non-admin requests', async () => {
    mockBearerKeyDao.findById.mockResolvedValue({
      id: 'key-2',
      name: 'other',
      token: 'token',
      enabled: true,
      accessType: 'all',
      createdBy: 'bob',
    });

    const req = makeReq({
      params: { id: 'key-2' },
    });
    const res = makeRes();

    await deleteBearerKey(req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(mockBearerKeyDao.delete).not.toHaveBeenCalled();
  });
});
