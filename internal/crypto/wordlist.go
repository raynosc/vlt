package crypto

// mnemonicWords is a 256-word list for encoding recovery keys as mnemonics.
// Each word represents one byte (0-255) of the key.
// Words are chosen to be short, distinct, and easy to spell.
var mnemonicWords = [256]string{
	"abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
	"abuse", "accept", "access", "accuse", "achieve", "acid", "acoustic", "acquire",
	"across", "act", "action", "actor", "actress", "actual", "adapt", "add",
	"address", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair",
	"afford", "afraid", "again", "age", "agent", "agree", "ahead", "aim",
	"air", "airport", "aisle", "alarm", "album", "alert", "alien", "align",
	"alive", "all", "allow", "almost", "alone", "along", "already", "also",
	"alter", "always", "amaze", "among", "amount", "amplify", "anchor", "ancient",
	"anger", "angle", "animal", "ankle", "announce", "annual", "another", "answer",
	"antenna", "antique", "anxiety", "any", "apart", "apology", "appear", "apple",
	"approve", "april", "arctic", "area", "arena", "argue", "arm", "armed",
	"armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art",
	"artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
	"asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
	"audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
	"avoid", "awake", "award", "aware", "awful", "axis", "baby", "bachelor",
	"bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana",
	"banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket",
	"battle", "beach", "bean", "beauty", "because", "become", "beef", "before",
	"begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit",
	"best", "better", "between", "beyond", "bicycle", "bike", "bind", "biology",
	"bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast",
	"bleak", "bless", "blind", "blood", "blossom", "blouse", "blue", "blur",
	"blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus",
	"book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce",
	"box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread",
	"breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli",
	"broken", "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy",
	"budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker",
	"burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer",
	"bypass", "cabin", "cable", "cactus", "cage", "cake", "call", "calm",
	"camera", "camp", "can", "canal", "cancel", "candle", "candy", "canoe",
}
