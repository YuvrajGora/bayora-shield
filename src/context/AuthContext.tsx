import React, { createContext, useContext, useState, useEffect } from 'react';
import { User, Role } from '../types/index.ts';
import { api, authStorage } from '../services/api.ts';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (credentials: { role?: Role; email?: string; password: string }) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    async function initAuth() {
      const savedUser = authStorage.getUser();
      const token = authStorage.getToken();

      if (savedUser && token) {
        try {
          const res = await api.getCurrentUser();
          setUser(res.user);
        } catch {
          authStorage.clear();
          setUser(null);
        }
      } else {
        // Strict Security: DO NOT automatically log in as admin.
        // User must explicitly authenticate with credentials.
        authStorage.clear();
        setUser(null);
      }
      setLoading(false);
    }

    initAuth();
  }, []);

  const login = async (credentials: { role?: Role; email?: string; password: string }) => {
    setLoading(true);
    try {
      const res = await api.login(credentials);
      setUser(res.user);
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    setLoading(true);
    try {
      await api.logout();
    } finally {
      setUser(null);
      setLoading(false);
    }
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
