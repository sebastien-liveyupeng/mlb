const { createClient } = require('@supabase/supabase-js');

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Parse body si c'est une string
  let body = req.body;
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch (e) {
      console.error('JSON parse error:', e);
      return res.status(400).json({ error: 'Invalid JSON in request body' });
    }
  }

  const { email, password } = body || {};

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  try {
    const supabase = createClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
    );

    const { data, error } = await supabase.auth.signInWithPassword({
      email: email,
      password: password
    });

    if (error) {
      return res.status(401).json({ error: error.message });
    }

        // Utilise la clé anon pour l'auth, puis la clé service_role pour la table
        const supabaseAuth = createClient(
          process.env.NEXT_PUBLIC_SUPABASE_URL,
          process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
        );
        const supabaseDb = createClient(
          process.env.NEXT_PUBLIC_SUPABASE_URL,
          process.env.SUPABASE_SERVICE_ROLE_KEY
        );

        const { data: authData, error: authError } = await supabaseAuth.auth.signInWithPassword({
          email: email,
          password: password
        });

        if (authError) {
          return res.status(401).json({ error: authError.message });
        }

        // Met à jour is_online dans public.users
        const { data: upsertData, error: upsertError } = await supabaseDb.from('users').upsert([
          {
            id: authData.user.id,
            email: authData.user.email,
            username: authData.user.user_metadata?.username || '',
            is_online: true
          }
        ], { onConflict: ['id'] });
        if (upsertError) {
          console.error('DB upsert error:', upsertError.message);
          return res.status(500).json({ error: 'DB upsert error', details: upsertError.message });
        }

        return res.status(200).json({
          success: true,
          message: 'Connexion réussie',
          user: {
            id: authData.user.id,
            email: authData.user.email,
            username: authData.user.user_metadata?.username
          },
          session: {
            access_token: authData.session.access_token,
            refresh_token: authData.session.refresh_token
          }
        });
      } catch (error) {
        console.error('Login error:', error.message, error.stack);
        return res.status(500).json({ error: 'Internal server error', details: error.message });
      }
    // Utilise la clé anon pour l'auth, puis la clé service_role pour la table
    const supabaseAuth = createClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
    );
    const supabaseDb = createClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL,
      process.env.SUPABASE_SERVICE_ROLE_KEY
    );

    const { data, error } = await supabaseAuth.auth.signInWithPassword({
      email: email,
      password: password
    });

    if (error) {
      return res.status(401).json({ error: error.message });
    }

    // Met à jour is_online dans public.users
    const upsertResult = await supabaseDb.from('users').upsert([
      {
        id: data.user.id,
        email: data.user.email,
        username: data.user.user_metadata?.username || '',
        is_online: true
      }
    ], { onConflict: ['id'] });
    if (upsertResult.error) {
      console.error('DB upsert error:', upsertResult.error.message);
    }
  } catch (error) {
    console.error('Login error:', error.message, error.stack);
    return res.status(500).json({
      error: 'Internal server error',
      details: error.message
    });
  }
};
