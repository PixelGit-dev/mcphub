import { Request, Response } from 'express';
import { ApiResponse, BearerKey, IUser } from '../types/index.js';
import { getBearerKeyDao } from '../dao/index.js';
import { loadSettings } from '../config/configManager.js';

type RequestUser = Pick<IUser, 'username' | 'isAdmin'>;

const getRequestUser = (req: Request): RequestUser | null => {
  const user = (req as any).user as RequestUser | undefined;
  return user?.username ? user : null;
};

const isAdminUser = (user: RequestUser | null): boolean => !!user?.isAdmin;

const canManageKey = (user: RequestUser | null, key: BearerKey | undefined): boolean => {
  if (!user || !key) {
    return false;
  }

  if (user.isAdmin) {
    return true;
  }

  return key.createdBy === user.username;
};

const getVisibleScopes = async (user: RequestUser | null) => {
  if (!user || user.isAdmin) {
    return {
      groups: null as Set<string> | null,
      servers: null as Set<string> | null,
    };
  }

  const settings = await loadSettings({
    username: user.username,
    password: '',
    isAdmin: false,
  });

  return {
    groups: new Set((settings.groups || []).flatMap((group) => [group.id, group.name])),
    servers: new Set(Object.keys(settings.mcpServers || {})),
  };
};

const normalizeRequestedScopes = async (
  user: RequestUser | null,
  accessType: BearerKey['accessType'],
  allowedGroups: unknown,
  allowedServers: unknown,
) => {
  const requestedGroups = Array.isArray(allowedGroups) ? allowedGroups : [];
  const requestedServers = Array.isArray(allowedServers) ? allowedServers : [];

  if (isAdminUser(user)) {
    return {
      allowedGroups: requestedGroups,
      allowedServers: requestedServers,
    };
  }

  const visibleScopes = await getVisibleScopes(user);
  const nextGroups = requestedGroups.filter((group): group is string =>
    typeof group === 'string' && visibleScopes.groups?.has(group),
  );
  const nextServers = requestedServers.filter((server): server is string =>
    typeof server === 'string' && visibleScopes.servers?.has(server),
  );

  if (accessType === 'groups' && requestedGroups.length > 0 && nextGroups.length === 0) {
    throw new Error('No visible groups selected');
  }

  if (accessType === 'servers' && requestedServers.length > 0 && nextServers.length === 0) {
    throw new Error('No visible servers selected');
  }

  if (
    accessType === 'custom' &&
    (requestedGroups.length > 0 || requestedServers.length > 0) &&
    nextGroups.length === 0 &&
    nextServers.length === 0
  ) {
    throw new Error('No visible groups or servers selected');
  }

  return {
    allowedGroups: nextGroups,
    allowedServers: nextServers,
  };
};

export const getBearerKeys = async (req: Request, res: Response): Promise<void> => {
  try {
    const user = getRequestUser(req);
    const dao = getBearerKeyDao();
    const keys = await dao.findAll();
    const response: ApiResponse = {
      success: true,
      data: isAdminUser(user) ? keys : keys.filter((key) => key.createdBy === user?.username),
    };
    res.json(response);
  } catch (error) {
    console.error('Failed to get bearer keys:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get bearer keys',
    });
  }
};

export const createBearerKey = async (req: Request, res: Response): Promise<void> => {
  try {
    const user = getRequestUser(req);
    if (!user) {
      res.status(401).json({ success: false, message: 'Authentication required' });
      return;
    }

    const { name, token, enabled, accessType, allowedGroups, allowedServers } =
      req.body as Partial<BearerKey>;

    if (!name || typeof name !== 'string') {
      res.status(400).json({ success: false, message: 'Key name is required' });
      return;
    }

    if (!token || typeof token !== 'string') {
      res.status(400).json({ success: false, message: 'Token value is required' });
      return;
    }

    if (!accessType || !['all', 'groups', 'servers', 'custom'].includes(accessType)) {
      res.status(400).json({ success: false, message: 'Invalid accessType' });
      return;
    }

    const dao = getBearerKeyDao();
    const normalizedScopes = await normalizeRequestedScopes(
      user,
      accessType,
      allowedGroups,
      allowedServers,
    );
    const key = await dao.create({
      name,
      token,
      enabled: enabled ?? true,
      accessType,
      allowedGroups: normalizedScopes.allowedGroups,
      allowedServers: normalizedScopes.allowedServers,
      createdBy: user.username,
    });

    const response: ApiResponse = {
      success: true,
      data: key,
    };
    res.status(201).json(response);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('No visible')) {
      res.status(400).json({
        success: false,
        message: error.message,
      });
      return;
    }
    console.error('Failed to create bearer key:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create bearer key',
    });
  }
};

export const updateBearerKey = async (req: Request, res: Response): Promise<void> => {
  try {
    const user = getRequestUser(req);
    const { id } = req.params;
    if (!id) {
      res.status(400).json({ success: false, message: 'Key id is required' });
      return;
    }

    const dao = getBearerKeyDao();
    const existing = await dao.findById(id);
    if (!existing) {
      res.status(404).json({ success: false, message: 'Key not found' });
      return;
    }

    if (!canManageKey(user, existing)) {
      res.status(403).json({ success: false, message: 'Cannot manage this bearer key' });
      return;
    }

    const { name, token, enabled, accessType, allowedGroups, allowedServers } =
      req.body as Partial<BearerKey>;

    const updates: Partial<BearerKey> = {};
    if (name !== undefined) updates.name = name;
    if (token !== undefined) updates.token = token;
    if (enabled !== undefined) updates.enabled = enabled;
    if (accessType !== undefined) {
      if (!['all', 'groups', 'servers', 'custom'].includes(accessType)) {
        res.status(400).json({ success: false, message: 'Invalid accessType' });
        return;
      }
      updates.accessType = accessType as BearerKey['accessType'];
    }
    if (allowedGroups !== undefined) {
      updates.allowedGroups = Array.isArray(allowedGroups) ? allowedGroups : [];
    }
    if (allowedServers !== undefined) {
      updates.allowedServers = Array.isArray(allowedServers) ? allowedServers : [];
    }

    if (
      accessType !== undefined ||
      allowedGroups !== undefined ||
      allowedServers !== undefined
    ) {
      const normalizedScopes = await normalizeRequestedScopes(
        user,
        (updates.accessType || existing.accessType) as BearerKey['accessType'],
        updates.allowedGroups ?? existing.allowedGroups,
        updates.allowedServers ?? existing.allowedServers,
      );
      updates.allowedGroups = normalizedScopes.allowedGroups;
      updates.allowedServers = normalizedScopes.allowedServers;
    }

    const updated = await dao.update(id, updates);
    if (!updated) {
      res.status(404).json({ success: false, message: 'Bearer key not found' });
      return;
    }

    const response: ApiResponse = {
      success: true,
      data: updated,
    };
    res.json(response);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('No visible')) {
      res.status(400).json({
        success: false,
        message: error.message,
      });
      return;
    }
    console.error('Failed to update bearer key:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update bearer key',
    });
  }
};

export const deleteBearerKey = async (req: Request, res: Response): Promise<void> => {
  try {
    const user = getRequestUser(req);
    const { id } = req.params;
    if (!id) {
      res.status(400).json({ success: false, message: 'Key id is required' });
      return;
    }

    const dao = getBearerKeyDao();
    const existing = await dao.findById(id);
    if (!existing) {
      res.status(404).json({ success: false, message: 'Key not found' });
      return;
    }

    if (!canManageKey(user, existing)) {
      res.status(403).json({ success: false, message: 'Cannot manage this bearer key' });
      return;
    }

    const deleted = await dao.delete(id);
    if (!deleted) {
      res.status(404).json({ success: false, message: 'Bearer key not found' });
      return;
    }

    const response: ApiResponse = {
      success: true,
    };
    res.json(response);
  } catch (error) {
    console.error('Failed to delete bearer key:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete bearer key',
    });
  }
};
