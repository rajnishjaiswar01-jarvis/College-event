require('dotenv').config();

const supabase = require('./supabase');

async function test() {
    const { data, error } = await supabase
        .from('registrations')
        .select('id')
        .limit(1);

    if (error) {
        console.error('❌ Supabase connection failed:');
        console.error(error);
        process.exit(1);
    }

    console.log('✅ Supabase connection successful!');
    console.log('📊 registrations table is accessible.');
    console.log('Data:', data);
}

test();