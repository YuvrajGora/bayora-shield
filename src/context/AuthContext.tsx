import React, { createContext, useContext, useState, useEffect } from 'react';
import { User, Role } from '../types/index.ts';
import { api, authStorage } from '../services/api.ts';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (role: Role) => Promise<void>;
  logout: () => void;
  switchRole: (role: Role) => Promise<void>;
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
        // Auto login as admin for initial quick preview if not logged in
        try {
          const res = await api.login('admin');
          setUser(res.user);
        } catch (err) {
          console.error('Initial login fallback error:', err);
        }
      }
      setLoading(false);
    }

    initAuth();
  }, []);

  const login = async (role: Role) => {
    setLoading(true);
    try {
      const res = await api.login(role);
      setUser(res.user);
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    authStorage.clear();
    setUser(null);
  };

  const switchRole = async (role: Role) => {
    await login(role);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, switchRole }}>
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
