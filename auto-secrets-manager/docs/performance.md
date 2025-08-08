# 📊 Performance

## Benchmarks

- **Branch detection**: ~2-5ms (cached)
- **Secret loading**: ~10-50ms (from cache)
- **Initial fetch**: ~100-500ms (from Infisical)
- **Memory usage**: ~5-15MB (Python process)
- **Cache size**: ~1-10KB per environment

## Optimization Tips

1. **Use path filtering**:

   ```json
   {
     "autoCommands": {
       "terraform": ["/infrastructure/**"] // Only load relevant secrets
     }
   }
   ```

2. **Adjust cache settings**:

   ```json
   {
     "cacheConfig": {
       "refresh_interval": "30m", // 30 minutes for less frequent fetches
       "cleanup_interval": "7d"
     }
   }
   ```

3. **Monitor cache efficiency**:
   ```bash
   auto-secrets inspect  # Check cache age and hit rates
   ```
