# Development

## Example

See [examples/basic-usage.ts](../../examples/basic-usage.ts) for a complete working example.

Run the example with:
```bash
npm start
```

## Running Tests

To run unit tests, run:
```bash
npm test
```

To run tests in dev mode with watch:
```bash
npm run test:dev
```

## Scripts

You can write custom scripts in the `scripts/` directory. See `scripts/example.ts` as an example.

Run your script with `npm run script -- example`

## Building

### Debug Builds

To compile a debug build, run:
```bash
npm run build
```

The build output will appear in the `./dist` folder.

### Production Builds

To compile a production build, run:
```bash
npm run lint:prod && npm run build
```

The build output will appear in the `./dist` folder.

## Linting

To check for code style issues:
```bash
npm run lint
```

To check for production code only:
```bash
npm run lint:prod
```

## Documentation

To generate TypeScript documentation:
```bash
npm run doc
```

Browse the generated docs in `docs/typedoc/index.html`
