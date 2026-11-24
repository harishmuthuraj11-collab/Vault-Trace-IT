import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import {
  INITIAL_USERS,
  INITIAL_ASSETS,
  INITIAL_ACTIVITY_LOGS,
  INITIAL_ALERTS,
  INITIAL_COMMAND_LOGS,
  DEFAULT_SETTINGS,
} from './src/data/mockData';
import { LaptopAsset, User, ActivityLog, AlertNotification, RemoteCommandLog, UserSettings } from './src/types';

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // In-memory data store with default seed
  let users: User[] = [...INITIAL_USERS];
  let assets: LaptopAsset[] = [...INITIAL_ASSETS];
  let activityLogs: ActivityLog[] = [...INITIAL_ACTIVITY_LOGS];
  let alerts: AlertNotification[] = [...INITIAL_ALERTS];
  let commandLogs: RemoteCommandLog[] = [...INITIAL_COMMAND_LOGS];
  let userSettingsMap: Record<string, UserSettings> = {
    'usr-101': { ...DEFAULT_SETTINGS, userId: 'usr-101' },
    'usr-102': { ...DEFAULT_SETTINGS, userId: 'usr-102' },
    'usr-103': { ...DEFAULT_SETTINGS, userId: 'usr-103' },
  };

  // Helper to add activity log
  const logActivity = (userId: string, username: string, securityEvent: string, deviceStatus: string) => {
    const newLog: ActivityLog = {
      id: `log-${Date.now()}`,
      userId,
      username,
      loginTime: new Date().toISOString().replace('T', ' ').substring(0, 19),
      logoutTime: null,
      deviceStatus,
      securityEvent,
      ipAddress: '192.168.1.100 (Secure SSL Gateway)',
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
    };
    activityLogs.unshift(newLog);
  };

  // Helper to add alert
  const addAlert = (userId: string, username: string, alertType: any, message: string, severity: 'critical' | 'warning' | 'info' = 'info') => {
    const newAlert: AlertNotification = {
      id: `alt-${Date.now()}`,
      userId,
      username,
      alertType,
      message,
      date: new Date().toISOString().replace('T', ' ').substring(0, 19),
      read: false,
      severity,
    };
    alerts.unshift(newAlert);
  };

  // --- API ROUTES ---

  // Health check
  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', service: 'VaultTrace IT Security Gateway', timestamp: new Date() });
  });

  // Authentication - Login
  app.post('/api/auth/login', (req, res) => {
    const { usernameOrEmail, password, rememberMe } = req.body;
    
    if (!usernameOrEmail || !password) {
      return res.status(400).json({ error: 'Username/Email and Password are required.' });
    }

    const foundUser = users.find(
      (u) => u.username.toLowerCase() === usernameOrEmail.toLowerCase() || u.email.toLowerCase() === usernameOrEmail.toLowerCase()
    );

    if (!foundUser) {
      return res.status(401).json({ error: 'Invalid credentials. User not found.' });
    }

    // Standard mock password verification
    if (password.length < 4) {
      return res.status(401).json({ error: 'Invalid password.' });
    }

    // Require OTP if 2FA enabled
    if (foundUser.twoFactorEnabled) {
      return res.json({
        requiresOtp: true,
        userId: foundUser.id,
        email: foundUser.email,
        message: `OTP sent to ${foundUser.email}. Please verify to complete login.`,
      });
    }

    foundUser.lastLogin = new Date().toISOString();
    logActivity(foundUser.id, foundUser.username, 'Login Succeeded via Standard Credentials', 'Online');
    addAlert(foundUser.id, foundUser.username, 'New Login', `Successful session started for user ${foundUser.username}.`, 'info');

    res.json({
      success: true,
      user: foundUser,
      token: `jwt-vaulttrace-${foundUser.id}-${Date.now()}`,
    });
  });

  // Auth - OTP Verification
  app.post('/api/auth/verify-otp', (req, res) => {
    const { userId, otp } = req.body;
    const foundUser = users.find((u) => u.id === userId);

    if (!foundUser) {
      return res.status(404).json({ error: 'User not found.' });
    }

    // Accept 6-digit OTP or '123456' or '654321'
    if (!otp || otp.length < 4) {
      return res.status(400).json({ error: 'Please enter a valid 6-digit OTP.' });
    }

    foundUser.lastLogin = new Date().toISOString();
    logActivity(foundUser.id, foundUser.username, 'Two-Factor Authentication Succeeded', 'Online');
    addAlert(foundUser.id, foundUser.username, 'New Login', `2FA OTP Verified for ${foundUser.username}.`, 'info');

    res.json({
      success: true,
      user: foundUser,
      token: `jwt-vaulttrace-${foundUser.id}-${Date.now()}`,
    });
  });

  // Registration Endpoint (User + Laptop Asset Registration)
  app.post('/api/auth/register', (req, res) => {
    const {
      fullName,
      username,
      email,
      mobile,
      password,
      brand,
      modelName,
      modelNumber,
      serialNumber,
      serviceId,
      workOrderNumber,
      manufacturingDate,
      operatingSystem,
      deviceNickname,
      allowDeviceTracking,
      allowLocationAccess,
      allowRemoteLock,
      acceptPrivacyPolicy,
    } = req.body;

    if (!fullName || !username || !email || !password) {
      return res.status(400).json({ error: 'Please fill in all mandatory user fields.' });
    }

    if (!acceptPrivacyPolicy) {
      return res.status(400).json({ error: 'Privacy Policy acceptance is mandatory.' });
    }

    // Check duplicate
    if (users.some((u) => u.username.toLowerCase() === username.toLowerCase() || u.email.toLowerCase() === email.toLowerCase())) {
      return res.status(400).json({ error: 'Username or Email already exists.' });
    }

    const newUserId = `usr-${Date.now()}`;
    const newUser: User = {
      id: newUserId,
      fullName,
      username,
      email,
      mobile: mobile || '+1 (555) 000-0000',
      role: 'user',
      twoFactorEnabled: false,
      createdAt: new Date().toISOString(),
      lastLogin: new Date().toISOString(),
    };

    users.push(newUser);

    // Register laptop if provided
    let newAsset: LaptopAsset | null = null;
    if (brand && modelName && serialNumber) {
      newAsset = {
        id: `asset-${Date.now()}`,
        userId: newUserId,
        userName: fullName,
        brand,
        modelName,
        modelNumber: modelNumber || `MN-${Math.floor(Math.random() * 90000 + 10000)}`,
        serialNumber,
        serviceId: serviceId || `SRV-${Math.floor(Math.random() * 900000 + 100000)}`,
        workOrderNumber: workOrderNumber || `WO-2026-${Math.floor(Math.random() * 9000 + 1000)}`,
        manufacturingDate: manufacturingDate || '2024-01-01',
        purchaseDate: new Date().toISOString().split('T')[0],
        warrantyStatus: 'Active - Corporate Warranty',
        operatingSystem: operatingSystem || 'Windows',
        deviceNickname: deviceNickname || `${fullName.split(' ')[0]}'s Laptop`,
        trackingEnabled: Boolean(allowDeviceTracking),
        locationAccessAllowed: Boolean(allowLocationAccess),
        remoteLockAllowed: Boolean(allowRemoteLock),
        privacyPolicyAccepted: Boolean(acceptPrivacyPolicy),
        status: 'Online',
        batteryLevel: 95,
        deviceHealth: 'Optimal',
        lastSeen: 'Just now',
        location: {
          latitude: 37.7749 + (Math.random() - 0.5) * 0.05,
          longitude: -122.4194 + (Math.random() - 0.5) * 0.05,
          address: 'Corporate Headquarters Office',
          city: 'San Francisco, CA',
          country: 'United States',
          accuracy: '± 5 meters',
          lastUpdated: new Date().toISOString().replace('T', ' ').substring(0, 19),
        },
        remoteLockStatus: 'Unlocked',
        alarmStatus: 'Off',
        imagePlaceholder: 'https://images.unsplash.com/photo-1588872657578-7efd1f1555ed?w=600&auto=format&fit=crop&q=80',
      };

      assets.push(newAsset);
    }

    userSettingsMap[newUserId] = { ...DEFAULT_SETTINGS, userId: newUserId };

    logActivity(newUserId, username, 'User Registration & Asset Provisioning Complete', 'Online');
    addAlert(newUserId, username, 'New Login', 'Welcome to VaultTrace IT! Your laptop asset is registered.', 'info');

    res.json({
      success: true,
      user: newUser,
      asset: newAsset,
      token: `jwt-vaulttrace-${newUserId}-${Date.now()}`,
    });
  });

  // Get Assets
  app.get('/api/assets', (req, res) => {
    const { userId, role } = req.query;

    if (role === 'admin' || role === 'security_analyst') {
      return res.json({ assets });
    }

    if (userId) {
      const userAssets = assets.filter((a) => a.userId === userId);
      return res.json({ assets: userAssets });
    }

    res.json({ assets });
  });

  // Search Device Endpoint
  app.get('/api/assets/search', (req, res) => {
    const { query, requestingUserId, role } = req.query;

    if (!query || typeof query !== 'string') {
      return res.json({ results: [] });
    }

    const q = query.trim().toLowerCase();

    // Filter matching assets
    const matched = assets.filter((a) => {
      const userMatch = a.userName.toLowerCase().includes(q);
      const serialMatch = a.serialNumber.toLowerCase().includes(q);
      const serviceMatch = a.serviceId.toLowerCase().includes(q);
      const modelMatch = a.modelNumber.toLowerCase().includes(q) || a.modelName.toLowerCase().includes(q);
      const brandMatch = a.brand.toLowerCase().includes(q);

      return userMatch || serialMatch || serviceMatch || modelMatch || brandMatch;
    });

    // Authorize display: display only registered device details the user is authorized to access
    const authorizedResults = matched.map((asset) => {
      const isOwner = asset.userId === requestingUserId;
      const isAdmin = role === 'admin' || role === 'security_analyst';

      if (isOwner || isAdmin) {
        return asset; // full access
      } else {
        // Redacted authorized view for non-owners in company directory
        return {
          ...asset,
          location: asset.trackingEnabled
            ? asset.location
            : {
                latitude: 0,
                longitude: 0,
                address: '[Tracking Permission Restricted by Owner]',
                city: 'Restricted',
                country: 'Restricted',
                accuracy: 'N/A',
                lastUpdated: 'Hidden',
              },
        };
      }
    });

    res.json({ results: authorizedResults });
  });

  // Register Asset Endpoint
  app.post('/api/assets/register', (req, res) => {
    const {
      userId,
      brand,
      modelName,
      modelNumber,
      serialNumber,
      serviceId,
      workOrderNumber,
      manufacturingDate,
      operatingSystem,
      deviceNickname,
      allowDeviceTracking,
      allowLocationAccess,
      allowRemoteLock,
      acceptPrivacyPolicy,
    } = req.body;

    const owner = users.find((u) => u.id === userId);
    const ownerName = owner ? owner.fullName : 'Registered User';

    const newAsset: LaptopAsset = {
      id: `asset-${Date.now()}`,
      userId,
      userName: ownerName,
      brand: brand || 'Generic',
      modelName: modelName || 'Laptop Workstation',
      modelNumber: modelNumber || `MN-${Math.floor(Math.random() * 80000 + 10000)}`,
      serialNumber: serialNumber || `SN-${Math.floor(Math.random() * 800000 + 100000)}`,
      serviceId: serviceId || `SRV-${Math.floor(Math.random() * 800000 + 100000)}`,
      workOrderNumber: workOrderNumber || `WO-${Math.floor(Math.random() * 80000 + 10000)}`,
      manufacturingDate: manufacturingDate || '2024-01-01',
      purchaseDate: new Date().toISOString().split('T')[0],
      warrantyStatus: 'Active Corporate SLA',
      operatingSystem: operatingSystem || 'Windows',
      deviceNickname: deviceNickname || `${ownerName}'s Corporate Laptop`,
      trackingEnabled: Boolean(allowDeviceTracking),
      locationAccessAllowed: Boolean(allowLocationAccess),
      remoteLockAllowed: Boolean(allowRemoteLock),
      privacyPolicyAccepted: Boolean(acceptPrivacyPolicy),
      status: 'Online',
      batteryLevel: 92,
      deviceHealth: 'Optimal',
      lastSeen: 'Just now',
      location: {
        latitude: 37.7749 + (Math.random() - 0.5) * 0.04,
        longitude: -122.4194 + (Math.random() - 0.5) * 0.04,
        address: 'VaultTrace Tech Hub',
        city: 'San Francisco, CA',
        country: 'United States',
        accuracy: '± 4 meters',
        lastUpdated: new Date().toISOString().replace('T', ' ').substring(0, 19),
      },
      remoteLockStatus: 'Unlocked',
      alarmStatus: 'Off',
      imagePlaceholder: 'https://images.unsplash.com/photo-1588872657578-7efd1f1555ed?w=600&auto=format&fit=crop&q=80',
    };

    assets.push(newAsset);
    logActivity(userId, owner ? owner.username : 'user', 'New Laptop Asset Registered', 'Online');
    addAlert(userId, owner ? owner.username : 'user', 'Tracking Enabled', `Registered new laptop ${newAsset.brand} ${newAsset.modelName}.`, 'info');

    res.json({ success: true, asset: newAsset });
  });

  // Remote Commands Endpoint (Lock, Unlock, Activate Alarm, Deactivate Alarm)
  app.post('/api/assets/:id/remote-command', (req, res) => {
    const { id } = req.params;
    const { command, executedBy, userId } = req.body; // 'Lock Laptop' | 'Unlock Laptop' | 'Activate Alarm' | 'Deactivate Alarm'

    const targetAsset = assets.find((a) => a.id === id);
    if (!targetAsset) {
      return res.status(404).json({ error: 'Asset not found.' });
    }

    if (!targetAsset.remoteLockAllowed && (command === 'Lock Laptop' || command === 'Unlock Laptop')) {
      return res.status(403).json({ error: 'Remote lock permission disabled on this device by owner.' });
    }

    let alertType: any = 'Remote Lock Activated';

    if (command === 'Lock Laptop') {
      targetAsset.remoteLockStatus = 'Locked';
      targetAsset.status = 'Locked';
      alertType = 'Remote Lock Activated';
    } else if (command === 'Unlock Laptop') {
      targetAsset.remoteLockStatus = 'Unlocked';
      targetAsset.status = 'Online';
      alertType = 'Remote Lock Deactivated';
    } else if (command === 'Activate Alarm') {
      targetAsset.alarmStatus = 'Active';
      targetAsset.status = 'Alarm Active';
      alertType = 'Alarm Activated';
    } else if (command === 'Deactivate Alarm') {
      targetAsset.alarmStatus = 'Off';
      targetAsset.status = 'Online';
      alertType = 'Alarm Deactivated';
    }

    const commandEntry: RemoteCommandLog = {
      id: `cmd-${Date.now()}`,
      assetId: id,
      deviceName: `${targetAsset.brand} ${targetAsset.modelName}`,
      command,
      status: 'Executed',
      timeExecuted: new Date().toISOString().replace('T', ' ').substring(0, 19),
      executedBy: executedBy || 'Authorized Operator',
    };

    commandLogs.unshift(commandEntry);

    const userObj = users.find((u) => u.id === targetAsset.userId);
    const username = userObj ? userObj.username : targetAsset.userName;

    logActivity(targetAsset.userId, username, `Remote Command Executed: ${command}`, targetAsset.status);
    addAlert(
      targetAsset.userId,
      username,
      alertType,
      `Security Command '${command}' triggered for ${targetAsset.brand} ${targetAsset.modelName} by ${executedBy}.`,
      command.includes('Activate') || command.includes('Lock') ? 'critical' : 'info'
    );

    res.json({
      success: true,
      asset: targetAsset,
      commandLog: commandEntry,
      commandLogs: commandLogs.filter((c) => c.assetId === id),
    });
  });

  // Get Command Logs for an Asset
  app.get('/api/assets/:id/command-logs', (req, res) => {
    const { id } = req.params;
    const logs = commandLogs.filter((c) => c.assetId === id);
    res.json({ commandLogs: logs });
  });

  // Toggle Permissions (Tracking, Location, Remote Lock)
  app.put('/api/assets/:id/permissions', (req, res) => {
    const { id } = req.params;
    const { trackingEnabled, locationAccessAllowed, remoteLockAllowed } = req.body;

    const targetAsset = assets.find((a) => a.id === id);
    if (!targetAsset) {
      return res.status(404).json({ error: 'Asset not found.' });
    }

    if (typeof trackingEnabled === 'boolean') {
      targetAsset.trackingEnabled = trackingEnabled;
    }
    if (typeof locationAccessAllowed === 'boolean') {
      targetAsset.locationAccessAllowed = locationAccessAllowed;
    }
    if (typeof remoteLockAllowed === 'boolean') {
      targetAsset.remoteLockAllowed = remoteLockAllowed;
    }

    const userObj = users.find((u) => u.id === targetAsset.userId);
    const username = userObj ? userObj.username : targetAsset.userName;

    logActivity(
      targetAsset.userId,
      username,
      `Device Permissions Updated (Tracking: ${targetAsset.trackingEnabled})`,
      targetAsset.status
    );

    addAlert(
      targetAsset.userId,
      username,
      targetAsset.trackingEnabled ? 'Tracking Enabled' : 'Tracking Disabled',
      `Location tracking permission for ${targetAsset.modelName} set to ${targetAsset.trackingEnabled ? 'ENABLED' : 'DISABLED'}.`,
      'warning'
    );

    res.json({ success: true, asset: targetAsset });
  });

  // Activity Logs Endpoint
  app.get('/api/activity-logs', (req, res) => {
    const { userId } = req.query;
    if (userId) {
      const filtered = activityLogs.filter((l) => l.userId === userId);
      return res.json({ activityLogs: filtered });
    }
    res.json({ activityLogs });
  });

  // Alerts Endpoint
  app.get('/api/alerts', (req, res) => {
    const { userId } = req.query;
    if (userId) {
      const filtered = alerts.filter((a) => a.userId === userId);
      return res.json({ alerts: filtered });
    }
    res.json({ alerts });
  });

  app.post('/api/alerts/mark-read', (req, res) => {
    const { alertId, userId } = req.body;
    if (alertId === 'all') {
      alerts.forEach((a) => {
        if (!userId || a.userId === userId) a.read = true;
      });
    } else {
      const target = alerts.find((a) => a.id === alertId);
      if (target) target.read = true;
    }
    res.json({ success: true, alerts });
  });

  // Settings Endpoint
  app.get('/api/settings/:userId', (req, res) => {
    const { userId } = req.params;
    const settings = userSettingsMap[userId] || { ...DEFAULT_SETTINGS, userId };
    res.json({ settings });
  });

  app.put('/api/settings/:userId', (req, res) => {
    const { userId } = req.params;
    userSettingsMap[userId] = { ...userSettingsMap[userId], ...req.body, userId };
    res.json({ success: true, settings: userSettingsMap[userId] });
  });

  // Reports Generation Endpoint
  app.get('/api/reports/generate', (req, res) => {
    const { reportType } = req.query; // 'asset' | 'user' | 'security' | 'login' | 'activity'

    let reportData: any = {};

    if (reportType === 'asset' || !reportType) {
      reportData = {
        title: 'Executive Laptop Asset Inventory Report',
        generatedAt: new Date().toISOString(),
        totalAssets: assets.length,
        onlineAssets: assets.filter((a) => a.status === 'Online').length,
        offlineAssets: assets.filter((a) => a.status === 'Offline').length,
        lockedAssets: assets.filter((a) => a.status === 'Locked' || a.status === 'Alarm Active').length,
        items: assets,
      };
    } else if (reportType === 'user') {
      reportData = {
        title: 'User Access & Registered Laptop Directory',
        generatedAt: new Date().toISOString(),
        totalUsers: users.length,
        usersWith2FA: users.filter((u) => u.twoFactorEnabled).length,
        items: users.map((u) => {
          const userAssets = assets.filter((a) => a.userId === u.id);
          return {
            ...u,
            registeredDevicesCount: userAssets.length,
            devices: userAssets.map((a) => `${a.brand} ${a.modelName} (${a.serialNumber})`),
          };
        }),
      };
    } else if (reportType === 'security') {
      reportData = {
        title: 'Cybersecurity Incident & Threat Assessment Report',
        generatedAt: new Date().toISOString(),
        totalAlerts: alerts.length,
        criticalAlerts: alerts.filter((a) => a.severity === 'critical').length,
        remoteCommandsExecuted: commandLogs.length,
        alerts,
        commandLogs,
      };
    } else if (reportType === 'login' || reportType === 'activity') {
      reportData = {
        title: 'User Login & Device Activity Audit Log',
        generatedAt: new Date().toISOString(),
        totalEvents: activityLogs.length,
        items: activityLogs,
      };
    }

    res.json(reportData);
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[VaultTrace IT Gateway] Running on http://localhost:${PORT}`);
  });
}

startServer();
