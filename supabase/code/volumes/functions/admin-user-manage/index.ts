import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  })
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) return json({ error: 'Não autenticado' }, 401)

    // Cliente com service role (operações admin)
    const supabaseAdmin = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
      { auth: { autoRefreshToken: false, persistSession: false } }
    )

    // Cliente com token do caller para validação
    const supabaseUser = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_ANON_KEY')!,
      {
        auth: { autoRefreshToken: false, persistSession: false },
        global: { headers: { Authorization: authHeader } },
      }
    )

    // Validar identidade do caller
    const { data: { user: caller }, error: authError } = await supabaseUser.auth.getUser()
    if (authError || !caller) return json({ error: 'Token inválido' }, 401)

    // Verificar se caller é admin
    const { data: callerProfile } = await supabaseAdmin
      .from('users')
      .select('role, is_active')
      .eq('id', caller.id)
      .single()

    if (!callerProfile?.is_active || !['admin', 'master_admin'].includes(callerProfile.role)) {
      return json({ error: 'Permissão negada' }, 403)
    }

    const body = await req.json()
    const { action } = body

    // ─── CREATE ───────────────────────────────────────────────
    if (action === 'create') {
      const { email, password, name, role, permissions, is_active, created_by } = body

      if (!email || !password || !name || !role) {
        return json({ error: 'Campos obrigatórios: email, password, name, role' }, 400)
      }

      if (password.length < 12) {
        return json({ error: 'Senha deve ter pelo menos 12 caracteres' }, 400)
      }

      // Apenas master_admin cria outros master_admin
      if (role === 'master_admin' && callerProfile.role !== 'master_admin') {
        return json({ error: 'Apenas master_admin pode criar outros master_admin' }, 403)
      }

      // Criar usuário no Supabase Auth
      const { data: newAuth, error: createError } = await supabaseAdmin.auth.admin.createUser({
        email: email.toLowerCase().trim(),
        password,
        email_confirm: true,
      })

      if (createError || !newAuth.user) {
        return json({ error: createError?.message || 'Erro ao criar usuário no Auth' }, 400)
      }

      // Criar perfil na tabela profiles
      const { data: profile, error: profileError } = await supabaseAdmin
        .from('users')
        .insert([{
          id: newAuth.user.id,
          email: email.toLowerCase().trim(),
          name: name.trim(),
          role,
          permissions: permissions ?? {},
          is_active: is_active ?? true,
          created_by: created_by ?? null,
        }])
        .select()
        .single()

      if (profileError) {
        // Rollback: remover usuário do Auth
        await supabaseAdmin.auth.admin.deleteUser(newAuth.user.id)
        return json({ error: profileError.message }, 400)
      }

      return json({ user: profile })
    }

    // ─── UPDATE_PASSWORD ──────────────────────────────────────
    if (action === 'update_password') {
      const { userId, password } = body

      if (!userId || !password) {
        return json({ error: 'Campos obrigatórios: userId, password' }, 400)
      }

      if (password.length < 12) {
        return json({ error: 'Senha deve ter pelo menos 12 caracteres' }, 400)
      }

      // Verificar permissão hierárquica
      const { data: targetProfile } = await supabaseAdmin
        .from('users')
        .select('role')
        .eq('id', userId)
        .single()

      if (!targetProfile) return json({ error: 'Usuário não encontrado' }, 404)

      if (targetProfile.role === 'master_admin' && callerProfile.role !== 'master_admin') {
        return json({ error: 'Apenas master_admin pode redefinir senha de outro master_admin' }, 403)
      }

      const { error } = await supabaseAdmin.auth.admin.updateUserById(userId, { password })
      if (error) return json({ error: error.message }, 400)

      return json({ success: true })
    }

    // ─── DISABLE ──────────────────────────────────────────────
    if (action === 'disable') {
      const { userId } = body
      if (!userId) return json({ error: 'Campo obrigatório: userId' }, 400)

      const { data: targetProfile } = await supabaseAdmin
        .from('users')
        .select('role')
        .eq('id', userId)
        .single()

      if (!targetProfile) return json({ error: 'Usuário não encontrado' }, 404)

      if (targetProfile.role === 'master_admin' && callerProfile.role !== 'master_admin') {
        return json({ error: 'Permissão negada' }, 403)
      }

      // Banir no Supabase Auth (10 anos = efetivamente desabilitado)
      await supabaseAdmin.auth.admin.updateUserById(userId, {
        ban_duration: '87600h',
      })

      return json({ success: true })
    }

    // ─── ENABLE ───────────────────────────────────────────────
    if (action === 'enable') {
      const { userId } = body
      if (!userId) return json({ error: 'Campo obrigatório: userId' }, 400)

      await supabaseAdmin.auth.admin.updateUserById(userId, {
        ban_duration: 'none',
      })

      return json({ success: true })
    }

    return json({ error: 'Ação desconhecida' }, 400)

  } catch (err) {
    console.error('[admin-user-manage] Erro:', err)
    return json({ error: 'Erro interno do servidor' }, 500)
  }
})
