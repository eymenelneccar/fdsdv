import { useState } from 'react';
import { useLocation } from 'wouter';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { GlassCard } from '@/components/ui/glass-card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
import { apiRequest } from '@/lib/queryClient';

export default function Login() {
  const [, setLocation] = useLocation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const loginMutation = useMutation({
    mutationFn: async (credentials: { username: string; password: string }) => {
      const response = await apiRequest('POST', '/api/auth/login', credentials);
      return response.json();
    },
    onSuccess: (user) => {
      queryClient.setQueryData(['/api/auth/user'], user);
      toast({
        title: 'تم تسجيل الدخول بنجاح',
        description: `مرحباً ${user.firstName || user.username}`,
      });
      setLocation('/');
    },
    onError: (error: any) => {
      toast({
        title: 'خطأ في تسجيل الدخول',
        description: error.message || 'فشل في تسجيل الدخول',
        variant: 'destructive',
      });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (username.trim() && password.trim()) {
      loginMutation.mutate({ username: username.trim(), password: password.trim() });
    }
  };

  return (
    <div className="min-h-screen gradient-bg flex items-center justify-center p-4">
      <GlassCard className="max-w-md w-full p-8">
        <div className="text-center mb-8">
          <div className="w-20 h-20 gradient-purple rounded-full flex items-center justify-center mx-auto mb-4 animate-glow">
            <i className="fas fa-chart-line text-3xl text-white"></i>
          </div>
          <h1 className="text-2xl font-bold mb-2" data-testid="text-login-title">تسجيل الدخول</h1>
          <p className="text-gray-300" data-testid="text-login-subtitle">IQR CONTROL</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="space-y-2">
            <Label htmlFor="username" className="text-right block">اسم المستخدم</Label>
            <Input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="أدخل اسم المستخدم"
              className="text-right"
              data-testid="input-username"
              required
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="password" className="text-right block">كلمة المرور</Label>
            <Input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="أدخل كلمة المرور"
              className="text-right"
              data-testid="input-password"
              required
            />
          </div>

          <Button
            type="submit"
            className="w-full gradient-purple hover:scale-105 transition-transform duration-300"
            disabled={loginMutation.isPending}
            data-testid="button-login"
          >
            {loginMutation.isPending ? 'جاري تسجيل الدخول...' : 'تسجيل الدخول'}
          </Button>
        </form>

        <div className="mt-6 text-center text-sm text-gray-400">
          <p>المستخدم الافتراضي: admin</p>
          <p>كلمة المرور: admin123</p>
        </div>
      </GlassCard>
    </div>
  );
}