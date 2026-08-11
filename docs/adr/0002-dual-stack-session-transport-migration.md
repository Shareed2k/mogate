# Migrate Session Transport with a dual-stack Remote Agent

The new Session Transport is versioned, authenticated, binary, and multiplexed,
while the Remote Agent temporarily continues to accept the legacy text control
commands. New clients use the new transport and rolling updates remain possible
without exposing an unauthenticated compatibility listener. Transport encryption
is deferred because the supported path is an authenticated `kubectl port-forward`.
