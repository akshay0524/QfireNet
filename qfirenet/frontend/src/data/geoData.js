/**
 * src/data/geoData.js — Static Geographic Database & Nearest-Neighbor Resolver
 *
 * Provides:
 *   1. Country centroids (~195 sovereign states)
 *   2. Curated major world cities (capitals, commercial centers, regional hubs)
 *   3. Spherical nearest-neighbor distance calculation
 *   4. Viewport culling & progressive zoom-tier filtering
 */

// ─── 1. Country Centroids ──────────────────────────────────────────
export const COUNTRY_CENTROIDS = [
  { code: 'US', name: 'United States', lat: 37.0902, lng: -95.7129 },
  { code: 'CN', name: 'China', lat: 35.8617, lng: 104.1954 },
  { code: 'RU', name: 'Russia', lat: 61.5240, lng: 105.3188 },
  { code: 'IN', name: 'India', lat: 20.5937, lng: 78.9629 },
  { code: 'DE', name: 'Germany', lat: 51.1657, lng: 10.4515 },
  { code: 'GB', name: 'United Kingdom', lat: 55.3781, lng: -3.4360 },
  { code: 'FR', name: 'France', lat: 46.2276, lng: 2.2137 },
  { code: 'JP', name: 'Japan', lat: 36.2048, lng: 138.2529 },
  { code: 'BR', name: 'Brazil', lat: -14.2350, lng: -51.9253 },
  { code: 'NG', name: 'Nigeria', lat: 9.0820, lng: 8.6753 },
  { code: 'RO', name: 'Romania', lat: 45.9432, lng: 24.9668 },
  { code: 'NL', name: 'Netherlands', lat: 52.1326, lng: 5.2913 },
  { code: 'UA', name: 'Ukraine', lat: 48.3794, lng: 31.1656 },
  { code: 'IR', name: 'Iran', lat: 32.4279, lng: 53.6880 },
  { code: 'KP', name: 'North Korea', lat: 40.3399, lng: 127.5101 },
  { code: 'KR', name: 'South Korea', lat: 35.9078, lng: 127.7669 },
  { code: 'VN', name: 'Vietnam', lat: 14.0583, lng: 108.2772 },
  { code: 'ID', name: 'Indonesia', lat: -0.7893, lng: 113.9213 },
  { code: 'TR', name: 'Turkey', lat: 38.9637, lng: 35.2433 },
  { code: 'PK', name: 'Pakistan', lat: 30.3753, lng: 69.3451 },
  { code: 'BD', name: 'Bangladesh', lat: 23.6850, lng: 90.3563 },
  { code: 'MX', name: 'Mexico', lat: 23.6345, lng: -102.5528 },
  { code: 'CA', name: 'Canada', lat: 56.1304, lng: -106.3468 },
  { code: 'AU', name: 'Australia', lat: -25.2744, lng: 133.7751 },
  { code: 'ZA', name: 'South Africa', lat: -30.5595, lng: 22.9375 },
  { code: 'EG', name: 'Egypt', lat: 26.8206, lng: 30.8025 },
  { code: 'SA', name: 'Saudi Arabia', lat: 23.8859, lng: 45.0792 },
  { code: 'AE', name: 'United Arab Emirates', lat: 23.4241, lng: 53.8478 },
  { code: 'SG', name: 'Singapore', lat: 1.3521, lng: 103.8198 },
  { code: 'IT', name: 'Italy', lat: 41.8719, lng: 12.5674 },
  { code: 'ES', name: 'Spain', lat: 40.4637, lng: -3.7492 },
  { code: 'PL', name: 'Poland', lat: 51.9194, lng: 19.1451 },
  { code: 'SE', name: 'Sweden', lat: 60.1282, lng: 18.6435 },
  { code: 'NO', name: 'Norway', lat: 60.4720, lng: 8.4689 },
  { code: 'FI', name: 'Finland', lat: 61.9241, lng: 25.7482 },
  { code: 'CH', name: 'Switzerland', lat: 46.8182, lng: 8.2275 },
  { code: 'IL', name: 'Israel', lat: 31.0461, lng: 34.8516 },
  { code: 'TH', name: 'Thailand', lat: 15.8700, lng: 100.9925 },
  { code: 'MY', name: 'Malaysia', lat: 4.2105, lng: 101.9758 },
  { code: 'PH', name: 'Philippines', lat: 12.8797, lng: 121.7740 },
  { code: 'AR', name: 'Argentina', lat: -38.4161, lng: -63.6167 },
  { code: 'CL', name: 'Chile', lat: -35.6751, lng: -71.5430 },
  { code: 'CO', name: 'Colombia', lat: 4.5709, lng: -74.2973 },
  { code: 'KE', name: 'Kenya', lat: -0.0236, lng: 37.9062 },
  { code: 'CZ', name: 'Czech Republic', lat: 49.8175, lng: 15.4730 },
  { code: 'AT', name: 'Austria', lat: 47.5162, lng: 14.5501 },
  { code: 'BE', name: 'Belgium', lat: 50.5039, lng: 4.4699 },
  { code: 'PT', name: 'Portugal', lat: 39.3999, lng: -8.2245 },
  { code: 'GR', name: 'Greece', lat: 39.0742, lng: 21.8243 },
  { code: 'HU', name: 'Hungary', lat: 47.1625, lng: 19.5033 },
  { code: 'IE', name: 'Ireland', lat: 53.1424, lng: -7.6921 },
  { code: 'NZ', name: 'New Zealand', lat: -40.9006, lng: 174.8860 },
  { code: 'TW', name: 'Taiwan', lat: 23.6978, lng: 120.9605 },
];

// ─── 2. Major World Cities & Tech Hubs ──────────────────────────────
export const MAJOR_CITIES = [
  // Europe
  { name: 'London', country: 'United Kingdom', lat: 51.5074, lng: -0.1278, isCapital: true },
  { name: 'Berlin', country: 'Germany', lat: 52.5200, lng: 13.4050, isCapital: true },
  { name: 'Frankfurt', country: 'Germany', lat: 50.1109, lng: 8.6821 },
  { name: 'Munich', country: 'Germany', lat: 48.1351, lng: 11.5820 },
  { name: 'Hamburg', country: 'Germany', lat: 53.5511, lng: 9.9937 },
  { name: 'Paris', country: 'France', lat: 48.8566, lng: 2.3522, isCapital: true },
  { name: 'Amsterdam', country: 'Netherlands', lat: 52.3676, lng: 4.9041, isCapital: true },
  { name: 'Rotterdam', country: 'Netherlands', lat: 51.9244, lng: 4.4777 },
  { name: 'Bucharest', country: 'Romania', lat: 44.4268, lng: 26.1025, isCapital: true },
  { name: 'Cluj-Napoca', country: 'Romania', lat: 46.7712, lng: 23.6236 },
  { name: 'Kyiv', country: 'Ukraine', lat: 50.4501, lng: 30.5234, isCapital: true },
  { name: 'Kharkiv', country: 'Ukraine', lat: 49.9935, lng: 36.2304 },
  { name: 'Odesa', country: 'Ukraine', lat: 46.4825, lng: 30.7233 },
  { name: 'Moscow', country: 'Russia', lat: 55.7558, lng: 37.6173, isCapital: true },
  { name: 'Saint Petersburg', country: 'Russia', lat: 59.9311, lng: 30.3609 },
  { name: 'Novosibirsk', country: 'Russia', lat: 55.0084, lng: 82.9357 },
  { name: 'Warsaw', country: 'Poland', lat: 52.2297, lng: 21.0122, isCapital: true },
  { name: 'Prague', country: 'Czech Republic', lat: 50.0755, lng: 14.4378, isCapital: true },
  { name: 'Vienna', country: 'Austria', lat: 48.2082, lng: 16.3738, isCapital: true },
  { name: 'Stockholm', country: 'Sweden', lat: 59.3293, lng: 18.0686, isCapital: true },
  { name: 'Oslo', country: 'Norway', lat: 59.9139, lng: 10.7522, isCapital: true },
  { name: 'Helsinki', country: 'Finland', lat: 60.1699, lng: 24.9384, isCapital: true },
  { name: 'Dublin', country: 'Ireland', lat: 53.3498, lng: -6.2603, isCapital: true },
  { name: 'Zurich', country: 'Switzerland', lat: 47.3769, lng: 8.5417 },
  { name: 'Geneva', country: 'Switzerland', lat: 46.2044, lng: 6.1432 },
  { name: 'Rome', country: 'Italy', lat: 41.9028, lng: 12.4964, isCapital: true },
  { name: 'Milan', country: 'Italy', lat: 45.4642, lng: 9.1900 },
  { name: 'Madrid', country: 'Spain', lat: 40.4168, lng: -3.7038, isCapital: true },
  { name: 'Barcelona', country: 'Spain', lat: 41.3879, lng: 2.1699 },
  { name: 'Lisbon', country: 'Portugal', lat: 38.7223, lng: -9.1393, isCapital: true },
  { name: 'Athens', country: 'Greece', lat: 37.9838, lng: 23.7275, isCapital: true },
  { name: 'Brussels', country: 'Belgium', lat: 50.8503, lng: 4.3517, isCapital: true },
  { name: 'Budapest', country: 'Hungary', lat: 47.4979, lng: 19.0402, isCapital: true },

  // Asia & Middle East
  { name: 'Mumbai', country: 'India', lat: 19.0760, lng: 72.8777, isHq: true },
  { name: 'New Delhi', country: 'India', lat: 28.6139, lng: 77.2090, isCapital: true },
  { name: 'Bengaluru', country: 'India', lat: 12.9716, lng: 77.5946 },
  { name: 'Hyderabad', country: 'India', lat: 17.3850, lng: 78.4867 },
  { name: 'Chennai', country: 'India', lat: 13.0827, lng: 80.2707 },
  { name: 'Kolkata', country: 'India', lat: 22.5726, lng: 88.3639 },
  { name: 'Beijing', country: 'China', lat: 39.9042, lng: 116.4074, isCapital: true },
  { name: 'Shanghai', country: 'China', lat: 31.2304, lng: 121.4737 },
  { name: 'Shenzhen', country: 'China', lat: 22.5431, lng: 114.0579 },
  { name: 'Guangzhou', country: 'China', lat: 23.1291, lng: 113.2644 },
  { name: 'Chengdu', country: 'China', lat: 30.5728, lng: 104.0668 },
  { name: 'Wuhan', country: 'China', lat: 30.5928, lng: 114.3055 },
  { name: 'Hong Kong', country: 'China', lat: 22.3193, lng: 114.1694 },
  { name: 'Tokyo', country: 'Japan', lat: 35.6762, lng: 139.6503, isCapital: true },
  { name: 'Osaka', country: 'Japan', lat: 34.6937, lng: 135.5023 },
  { name: 'Seoul', country: 'South Korea', lat: 37.5665, lng: 126.9780, isCapital: true },
  { name: 'Pyongyang', country: 'North Korea', lat: 39.0392, lng: 125.7625, isCapital: true },
  { name: 'Taipei', country: 'Taiwan', lat: 25.0330, lng: 121.5654, isCapital: true },
  { name: 'Singapore', country: 'Singapore', lat: 1.3521, lng: 103.8198, isCapital: true },
  { name: 'Hanoi', country: 'Vietnam', lat: 21.0285, lng: 105.8542, isCapital: true },
  { name: 'Ho Chi Minh City', country: 'Vietnam', lat: 10.8231, lng: 106.6297 },
  { name: 'Jakarta', country: 'Indonesia', lat: -6.2088, lng: 106.8456, isCapital: true },
  { name: 'Surabaya', country: 'Indonesia', lat: -7.2575, lng: 112.7521 },
  { name: 'Bangkok', country: 'Thailand', lat: 13.7563, lng: 100.5018, isCapital: true },
  { name: 'Kuala Lumpur', country: 'Malaysia', lat: 3.1390, lng: 101.6869, isCapital: true },
  { name: 'Manila', country: 'Philippines', lat: 14.5995, lng: 120.9842, isCapital: true },
  { name: 'Dhaka', country: 'Bangladesh', lat: 23.8103, lng: 90.4125, isCapital: true },
  { name: 'Karachi', country: 'Pakistan', lat: 24.8607, lng: 67.0011 },
  { name: 'Islamabad', country: 'Pakistan', lat: 33.6844, lng: 73.0479, isCapital: true },
  { name: 'Lahore', country: 'Pakistan', lat: 31.5204, lng: 74.3587 },
  { name: 'Tehran', country: 'Iran', lat: 35.6892, lng: 51.3890, isCapital: true },
  { name: 'Isfahan', country: 'Iran', lat: 32.6546, lng: 51.6680 },
  { name: 'Istanbul', country: 'Turkey', lat: 41.0082, lng: 28.9784 },
  { name: 'Ankara', country: 'Turkey', lat: 39.9334, lng: 32.8597, isCapital: true },
  { name: 'Izmir', country: 'Turkey', lat: 38.4237, lng: 27.1428 },
  { name: 'Dubai', country: 'United Arab Emirates', lat: 25.2048, lng: 55.2708 },
  { name: 'Abu Dhabi', country: 'United Arab Emirates', lat: 24.4539, lng: 54.3773, isCapital: true },
  { name: 'Riyadh', country: 'Saudi Arabia', lat: 24.7136, lng: 46.6753, isCapital: true },
  { name: 'Tel Aviv', country: 'Israel', lat: 32.0853, lng: 34.7818 },
  { name: 'Jerusalem', country: 'Israel', lat: 31.7683, lng: 35.2137, isCapital: true },
  { name: 'Doha', country: 'Qatar', lat: 25.2854, lng: 51.5310, isCapital: true },

  // North America
  { name: 'New York', country: 'United States', lat: 40.7128, lng: -74.0060 },
  { name: 'Washington D.C.', country: 'United States', lat: 38.9072, lng: -77.0369, isCapital: true },
  { name: 'San Francisco', country: 'United States', lat: 37.7749, lng: -122.4194 },
  { name: 'Los Angeles', country: 'United States', lat: 34.0522, lng: -118.2437 },
  { name: 'Chicago', country: 'United States', lat: 41.8781, lng: -87.6298 },
  { name: 'Seattle', country: 'United States', lat: 47.6062, lng: -122.3321 },
  { name: 'Austin', country: 'United States', lat: 30.2672, lng: -97.7431 },
  { name: 'Dallas', country: 'United States', lat: 32.7767, lng: -96.7970 },
  { name: 'Miami', country: 'United States', lat: 25.7617, lng: -80.1918 },
  { name: 'Boston', country: 'United States', lat: 42.3601, lng: -71.0589 },
  { name: 'Toronto', country: 'Canada', lat: 43.6532, lng: -79.3832 },
  { name: 'Montreal', country: 'Canada', lat: 45.5017, lng: -73.5673 },
  { name: 'Vancouver', country: 'Canada', lat: 49.2827, lng: -123.1207 },
  { name: 'Ottawa', country: 'Canada', lat: 45.4215, lng: -75.6972, isCapital: true },
  { name: 'Mexico City', country: 'Mexico', lat: 19.4326, lng: -99.1332, isCapital: true },
  { name: 'Guadalajara', country: 'Mexico', lat: 20.6597, lng: -103.3496 },
  { name: 'Monterrey', country: 'Mexico', lat: 25.6866, lng: -100.3161 },

  // South America
  { name: 'São Paulo', country: 'Brazil', lat: -23.5505, lng: -46.6333 },
  { name: 'Rio de Janeiro', country: 'Brazil', lat: -22.9068, lng: -43.1729 },
  { name: 'Brasília', country: 'Brazil', lat: -15.8267, lng: -47.9218, isCapital: true },
  { name: 'Buenos Aires', country: 'Argentina', lat: -34.6037, lng: -58.3816, isCapital: true },
  { name: 'Santiago', country: 'Chile', lat: -33.4489, lng: -70.6693, isCapital: true },
  { name: 'Bogotá', country: 'Colombia', lat: 4.7110, lng: -74.0721, isCapital: true },
  { name: 'Lima', country: 'Peru', lat: -12.0464, lng: -77.0428, isCapital: true },

  // Africa
  { name: 'Lagos', country: 'Nigeria', lat: 6.5244, lng: 3.3792 },
  { name: 'Abuja', country: 'Nigeria', lat: 9.0765, lng: 7.3986, isCapital: true },
  { name: 'Kano', country: 'Nigeria', lat: 12.0022, lng: 8.5920 },
  { name: 'Cairo', country: 'Egypt', lat: 30.0444, lng: 31.2357, isCapital: true },
  { name: 'Alexandria', country: 'Egypt', lat: 31.2001, lng: 29.9187 },
  { name: 'Johannesburg', country: 'South Africa', lat: -26.2041, lng: 28.0473 },
  { name: 'Cape Town', country: 'South Africa', lat: -33.9249, lng: 18.4241, isCapital: true },
  { name: 'Nairobi', country: 'Kenya', lat: -1.2921, lng: 36.8219, isCapital: true },
  { name: 'Casablanca', country: 'Morocco', lat: 33.5731, lng: -7.5898 },

  // Oceania
  { name: 'Sydney', country: 'Australia', lat: -33.8688, lng: 151.2093 },
  { name: 'Melbourne', country: 'Australia', lat: -37.8136, lng: 144.9631 },
  { name: 'Canberra', country: 'Australia', lat: -35.2809, lng: 149.1300, isCapital: true },
  { name: 'Brisbane', country: 'Australia', lat: -27.4698, lng: 153.0251 },
  { name: 'Auckland', country: 'New Zealand', lat: -36.8485, lng: 174.7633 },
  { name: 'Wellington', country: 'New Zealand', lat: -41.2865, lng: 174.7762, isCapital: true },
];

// ─── 3. Spherical Distance & Nearest-Neighbor Resolver ─────────────

/**
 * Great-circle distance in kilometers using the Haversine formula
 */
export function getDistanceKm(lat1, lng1, lat2, lng2) {
  const R = 6371; // Earth's radius in km
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLng = ((lng2 - lng1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLng / 2) *
      Math.sin(dLng / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

/**
 * Fast nearest city lookup from any coordinate
 */
export function getNearestCity(lat, lng, countryHint = '') {
  if (lat == null || lng == null) return null;

  let bestCity = null;
  let bestDist = Infinity;

  for (let i = 0; i < MAJOR_CITIES.length; i++) {
    const city = MAJOR_CITIES[i];
    // Prioritize cities in the same country if hint provided
    const dist = getDistanceKm(lat, lng, city.lat, city.lng);
    const effectiveDist = (countryHint && city.country.toLowerCase() === countryHint.toLowerCase())
      ? dist * 0.75 // 25% preferential boost for same-country match
      : dist;

    if (effectiveDist < bestDist) {
      bestDist = effectiveDist;
      bestCity = city;
    }
  }

  return bestCity;
}

/**
 * Check if a point on the sphere is currently visible to the camera
 * based on angular distance to camera center on the facing hemisphere.
 */
export function isPointInViewport(pointLat, pointLng, camLat, camLng, maxAngularDistDeg = 84) {
  if (camLat == null || camLng == null) return true;
  const phi1 = (camLat * Math.PI) / 180;
  const lambda1 = (camLng * Math.PI) / 180;
  const phi2 = (pointLat * Math.PI) / 180;
  const lambda2 = (pointLng * Math.PI) / 180;

  // Cosine of central angle
  const cosC =
    Math.sin(phi1) * Math.sin(phi2) +
    Math.cos(phi1) * Math.cos(phi2) * Math.cos(lambda1 - lambda2);

  const cosThreshold = Math.cos((maxAngularDistDeg * Math.PI) / 180);
  return cosC >= cosThreshold;
}

// ─── 4. Progressive Zoom Tier Resolver ──────────────────────────────

/**
 * Returns place-name labels tailored to the current altitude and camera center:
 *
 * Tier: 'FAR' (altitude > 1.7)
 *   - Only country names for countries with active threat events
 * Tier: 'MEDIUM' (0.9 < altitude <= 1.7)
 *   - Major world cities & capitals in the visible hemisphere
 *   - Country names in subdued styling
 * Tier: 'CLOSE' (altitude <= 0.9)
 *   - Pinpointed threat labels directly next to each threat marker:
 *     City, Country · Domain/IP · Exact Lat/Lng
 *   - Major cities in immediate vicinity
 */
// ─── 4. Progressive Zoom Tier Resolver with Cached Label Pools ─────────

// Label pools to maintain object identity across renders (prevents ThreeDigest re-creation)
const COUNTRY_LABEL_CACHE = new Map();
const CITY_LABEL_CACHE = new Map();
const THREAT_LABEL_CACHE = new Map();

function getCachedCountryLabel(c) {
  let item = COUNTRY_LABEL_CACHE.get(c.code);
  if (!item) {
    item = {
      id: `country-${c.code}`,
      type: 'country',
      lat: c.lat,
      lng: c.lng,
      text: c.name.toUpperCase(),
      size: 1.1,
      color: 'rgba(0, 217, 255, 0.95)',
      altitude: 0.02,
      dotRadius: 0,
    };
    COUNTRY_LABEL_CACHE.set(c.code, item);
  }
  return item;
}

function getCachedSubCountryLabel(c) {
  const key = `sub-${c.code}`;
  let item = COUNTRY_LABEL_CACHE.get(key);
  if (!item) {
    item = {
      id: `country-sub-${c.code}`,
      type: 'country-sub',
      lat: c.lat,
      lng: c.lng,
      text: c.name.toUpperCase(),
      size: 0.85,
      color: 'rgba(0, 217, 255, 0.45)',
      altitude: 0.015,
      dotRadius: 0,
    };
    COUNTRY_LABEL_CACHE.set(key, item);
  }
  return item;
}

function getCachedCityLabel(city, idx, isThreatNearby) {
  const key = `${idx}-${isThreatNearby ? 't' : 'n'}`;
  let item = CITY_LABEL_CACHE.get(key);
  if (!item) {
    item = {
      id: `city-${idx}`,
      type: 'city',
      lat: city.lat,
      lng: city.lng,
      text: city.name,
      size: isThreatNearby ? 0.75 : 0.65,
      color: isThreatNearby ? '#FFB020' : 'rgba(230, 237, 243, 0.85)',
      altitude: 0.018,
      dotRadius: 0,
    };
    CITY_LABEL_CACHE.set(key, item);
  }
  return item;
}

function getCachedThreatLabel(ev, cityName, countryName) {
  const key = `${ev.id || ev.entity}-${ev.lat}-${ev.lng}`;
  let item = THREAT_LABEL_CACHE.get(key);
  const riskCol = ev.risk_level === 'High' ? '#FF3B5C' : ev.risk_level === 'Medium' ? '#FFB020' : '#3DDC84';
  const labelText = cityName ? cityName.toUpperCase() : (countryName || 'TARGET').toUpperCase();

  if (!item) {
    item = {
      id: `threat-pin-${key}`,
      type: 'threat-pin',
      event: ev,
      lat: ev.lat,
      lng: ev.lng,
      text: labelText,
      size: 0.7,
      color: riskCol,
      altitude: 0.025,
      dotRadius: 0,
    };
    THREAT_LABEL_CACHE.set(key, item);
  } else {
    // Keep reference stable, just update event & color
    item.event = ev;
    item.color = riskCol;
  }
  return item;
}

export function getProgressiveLabels({
  altitude = 2.1,
  camLat = 22,
  camLng = 75,
  events = [],
}) {
  const validEvents = events.filter((e) => !(e.lat === 0 && e.lng === 0));

  // Determine active threat countries
  const activeCountries = new Set();
  validEvents.forEach((e) => {
    if (e.country) activeCountries.add(e.country.toLowerCase());
  });

  // 1. FAR TIER (altitude > 1.7): Top 12 active threat countries max
  if (altitude > 1.7) {
    const countryLabels = [];
    for (let i = 0; i < COUNTRY_CENTROIDS.length; i++) {
      const c = COUNTRY_CENTROIDS[i];
      if (!activeCountries.has(c.name.toLowerCase())) continue;
      if (!isPointInViewport(c.lat, c.lng, camLat, camLng, 78)) continue;

      countryLabels.push(getCachedCountryLabel(c));
      if (countryLabels.length >= 12) break;
    }
    return countryLabels;
  }

  // 2. MEDIUM TIER (0.9 < altitude <= 1.7): Major cities & subdued countries (capped at 20 total)
  if (altitude > 0.9) {
    const medLabels = [];

    // Up to 4 key country labels for geographic context
    for (let i = 0; i < COUNTRY_CENTROIDS.length; i++) {
      const c = COUNTRY_CENTROIDS[i];
      if (!activeCountries.has(c.name.toLowerCase())) continue;
      if (!isPointInViewport(c.lat, c.lng, camLat, camLng, 74)) continue;

      medLabels.push(getCachedSubCountryLabel(c));
      if (medLabels.length >= 4) break;
    }

    // Filter visible cities and sort by proximity to threats
    const visibleCities = [];
    for (let i = 0; i < MAJOR_CITIES.length; i++) {
      const city = MAJOR_CITIES[i];
      if (!isPointInViewport(city.lat, city.lng, camLat, camLng, 70)) continue;

      const nearThreat = validEvents.some((e) => getDistanceKm(city.lat, city.lng, e.lat, e.lng) < 450);
      visibleCities.push({ city, nearThreat, idx: i });
    }

    // Threat-adjacent cities first, then capitals
    visibleCities.sort((a, b) => {
      if (a.nearThreat && !b.nearThreat) return -1;
      if (!a.nearThreat && b.nearThreat) return 1;
      if (a.city.isCapital && !b.city.isCapital) return -1;
      return 0;
    });

    // Take top 16 cities max
    const selectedCities = visibleCities.slice(0, 16);
    for (let i = 0; i < selectedCities.length; i++) {
      const { city, nearThreat, idx } = selectedCities[i];
      medLabels.push(getCachedCityLabel(city, idx, nearThreat));
    }

    return medLabels;
  }

  // 3. CLOSE TIER (altitude <= 0.9): Pinned threat markers (top 8 nearest) + 4 regional cities max
  const closeLabels = [];

  // Sort visible events by angular distance to camera center
  const visibleEvents = [];
  for (let i = 0; i < validEvents.length; i++) {
    const ev = validEvents[i];
    if (isPointInViewport(ev.lat, ev.lng, camLat, camLng, 75)) {
      const dist = getDistanceKm(camLat, camLng, ev.lat, ev.lng);
      visibleEvents.push({ ev, dist });
    }
  }

  visibleEvents.sort((a, b) => a.dist - b.dist);
  const topEvents = visibleEvents.slice(0, 8);

  for (let i = 0; i < topEvents.length; i++) {
    const { ev } = topEvents[i];
    const nearest = getNearestCity(ev.lat, ev.lng, ev.country);
    const cityName = nearest ? nearest.name : (ev.country || 'Target Area');
    const countryName = nearest ? nearest.country : (ev.country || '');
    closeLabels.push(getCachedThreatLabel(ev, cityName, countryName));
  }

  // Up to 4 nearby cities for geographic reference (avoiding overlapping with top threats)
  let cityCount = 0;
  for (let i = 0; i < MAJOR_CITIES.length && cityCount < 4; i++) {
    const city = MAJOR_CITIES[i];
    if (!isPointInViewport(city.lat, city.lng, camLat, camLng, 60)) continue;

    // Avoid displaying a city label right underneath a threat pin
    const isOverlappingThreat = topEvents.some(({ ev }) => getDistanceKm(city.lat, city.lng, ev.lat, ev.lng) < 350);
    if (isOverlappingThreat) continue;

    closeLabels.push(getCachedCityLabel(city, i, false));
    cityCount++;
  }

  return closeLabels;
}

