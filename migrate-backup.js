require('dotenv').config();
const fs = require('fs');
const { Pool } = require('pg');

const BACKUP_PATH = `${process.env.USERPROFILE}/Downloads/freshfare-registrations-backup.json`;

if (!process.env.DATABASE_URL) {
    console.error('❌ DATABASE_URL is missing from .env');
    process.exit(1);
}

if (!fs.existsSync(BACKUP_PATH)) {
    console.error(`❌ Backup file not found: ${BACKUP_PATH}`);
    process.exit(1);
}

const backup = JSON.parse(fs.readFileSync(BACKUP_PATH, 'utf8'));
const registrations = backup.registrations || [];

console.log(`📦 Backup registrations found: ${registrations.length}`);

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_SSL === 'true'
        ? { rejectUnauthorized: false }
        : false
});

async function migrate() {
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        console.log('🔌 Connected to PostgreSQL.');
        console.log('🚀 Starting migration...');

        let inserted = 0;
        let updated = 0;
        let skipped = 0;

        for (const r of registrations) {
            const existing = await client.query(
                `SELECT id FROM registrations
                 WHERE id = $1 OR email = $2
                 LIMIT 1`,
                [r.id, r.email]
            );

            if (existing.rows.length > 0) {
                const existingId = existing.rows[0].id;

                await client.query(
                    `UPDATE registrations
                     SET
                        name = $1,
                        email = $2,
                        phone = $3,
                        role = $4,
                        status = $5,
                        checkin_token = $6,
                        attended = $7,
                        attended_at = $8,
                        created_at = $9,
                        updated_at = $10
                     WHERE id = $11`,
                    [
                        r.name,
                        r.email,
                        r.phone,
                        r.role,
                        r.status,
                        r.checkin_token || null,
                        Number(r.attended) || 0,
                        r.attended_at || null,
                        r.created_at,
                        r.updated_at,
                        existingId
                    ]
                );

                console.log(`🔄 Updated: ${r.id} - ${r.email}`);
                updated++;
            } else {
                await client.query(
                    `INSERT INTO registrations
                    (
                        id,
                        name,
                        email,
                        phone,
                        role,
                        status,
                        checkin_token,
                        attended,
                        attended_at,
                        created_at,
                        updated_at
                    )
                    VALUES
                    ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
                    [
                        r.id,
                        r.name,
                        r.email,
                        r.phone,
                        r.role,
                        r.status,
                        r.checkin_token || null,
                        Number(r.attended) || 0,
                        r.attended_at || null,
                        r.created_at,
                        r.updated_at
                    ]
                );

                console.log(`✅ Inserted: ${r.id} - ${r.email}`);
                inserted++;
            }
        }

        /*
         * Reset PostgreSQL identity sequence so the next
         * automatically generated ID does not collide.
         */
        await client.query(`
            SELECT setval(
                pg_get_serial_sequence('registrations', 'id'),
                COALESCE((SELECT MAX(id) FROM registrations), 1),
                true
            );
        `);

        const countResult = await client.query(`
            SELECT COUNT(*)::int AS count
            FROM registrations
        `);

        const verifyResult = await client.query(`
            SELECT id, name, email, status, attended
            FROM registrations
            ORDER BY id
        `);

        await client.query('COMMIT');

        console.log('\n================================');
        console.log('✅ MIGRATION COMPLETED');
        console.log('================================');
        console.log(`Backup records : ${registrations.length}`);
        console.log(`Inserted       : ${inserted}`);
        console.log(`Updated        : ${updated}`);
        console.log(`Skipped        : ${skipped}`);
        console.log(`PostgreSQL     : ${countResult.rows[0].count}`);
        console.log('================================\n');

        console.table(verifyResult.rows);

    } catch (error) {
        await client.query('ROLLBACK');

        console.error('\n❌ MIGRATION FAILED');
        console.error(error.message);
        console.error('🔒 Transaction rolled back. No partial migration was saved.');

        process.exitCode = 1;
    } finally {
        client.release();
        await pool.end();
    }
}

migrate();
