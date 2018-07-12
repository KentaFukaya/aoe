#include "ext4_h/ext4.h"
#include "ext4_h/extents_status.h"

#include "ext4_h/cache_status.h"

#define PARTTION_START 1796644864

int __init init_cs(void)
{
	printk("init_cs\n");
    return 0;
}

void exit_cs(void)
{
	printk("exit_cs\n");
}


static struct extent_status *
cs_alloc_extent(struct inode *inode, struct extent_status *newes)
{
	struct extent_status *es;
	es = kmalloc(sizeof(struct extent_status), GFP_KERNEL);
	if (!es)
		return NULL;

	es->es_lblk = newes->es_lblk;
	es->es_len = newes->es_len;
	es->es_pblk = newes->es_pblk;
	es->inode = newes->inode;//added

	EXT4_I(inode)->i_es_all_nr++;
	return es;
}

static void cs_free_extent(struct inode *inode, struct extent_status *es)
{
    EXT4_I(inode)->i_es_all_nr--;
}

static int cs_can_be_merged(struct extent_status *es1,
				 struct extent_status *es2){
	if (!es1->inode)
		return 0;
	if (ext4_es_type(es1) != ext4_es_type(es2))
		return 0;
	if (((__u64) es1->es_pblk) + es1->es_len != es2->es_pblk)
		return 0;

	if ((ext4_es_pblock(es1) <= ext4_es_pblock(es2)) &&
		(ext4_es_pblock(es1) + es1->es_len >= ext4_es_pblock(es2))){
	    if (es1->inode->i_ino == es2->inode->i_ino)
			return 1;
		else
			return 0;
	}

	return 0;
}

static struct extent_status *
cs_try_to_merge_left(struct inode *inode, struct extent_status *es)
{
	struct ext4_es_tree *tree = &EXT4_I(inode)->i_es_tree;
	struct extent_status *es1;
	struct rb_node *node;

	node = rb_prev(&es->rb_node);
	if (!node)
		return es;

	es1 = rb_entry(node, struct extent_status, rb_node);
	if (cs_can_be_merged(es1, es)) {
		es1->es_len += es->es_len;
		if (ext4_es_is_referenced(es))
			ext4_es_set_referenced(es1);
		rb_erase(&es->rb_node, &tree->root);
		cs_free_extent(inode, es);
		es = es1;
	}

	return es;
}

static struct extent_status *
cs_try_to_merge_right(struct inode *inode, struct extent_status *es)
{
	struct ext4_es_tree *tree = &EXT4_I(inode)->i_es_tree;
	struct extent_status *es1;
	struct rb_node *node;

	node = rb_next(&es->rb_node);
	if (!node)
		return es;

	es1 = rb_entry(node, struct extent_status, rb_node);
	if (cs_can_be_merged(es, es1)) {
		es->es_len += es1->es_len;
		if (ext4_es_is_referenced(es1))
			ext4_es_set_referenced(es);
		rb_erase(node, &tree->root);
		cs_free_extent(inode, es1);
	}

	return es;
}

static inline ext4_fsblk_t cs_end(struct extent_status *es)
{
	return es->es_pblk + es->es_len - 1;
}

static int __cs_insert_extent(struct inode *inode, struct extent_status *newes)
{
	struct ext4_es_tree *tree = &EXT4_I(inode)->i_es_tree;
	struct rb_node **p = &tree->root.rb_node;
	struct rb_node *parent = NULL;
	struct extent_status *es;
	
	//printk("[__cs_insert_extent] es nr %u\n", EXT4_I(inode)->i_es_all_nr);
	if(!tree)
		return 0;
	
	while (*p) {
		parent = *p;
		es = rb_entry(parent, struct extent_status, rb_node);

		if (newes->es_pblk < es->es_pblk) {
			if (cs_can_be_merged(newes, es)) {
				es->es_pblk = newes->es_pblk;
				es->es_len += newes->es_len;
				if (ext4_es_is_written(es) ||
				    ext4_es_is_unwritten(es))
					ext4_es_store_pblock(es,
							     newes->es_pblk);
				es = cs_try_to_merge_left(inode, es);
				goto out;
			}
			p = &(*p)->rb_left;
		} else if (newes->es_pblk > cs_end(es)) {
			if (cs_can_be_merged(es, newes)) {
				es->es_len += newes->es_len;
				es = cs_try_to_merge_right(inode, es);
				goto out;
			}
			p = &(*p)->rb_right;
		} else {
			goto out;
		}
	}
	es = cs_alloc_extent(inode, newes);
	rb_link_node(&es->rb_node, parent, p);
	rb_insert_color(&es->rb_node, &tree->root);
out:
	return 0;
}

int cs_insert_extent(struct inode *inode, ext4_lblk_t lblk,
			  ext4_lblk_t len, ext4_fsblk_t pblk,
			  unsigned int status)
{
	struct extent_status newes;
	int err = 0;
	struct inode *tree_inode;

	tree_inode = ilookup(inode->i_sb, 2);
	if(!tree_inode){
		printk("cant get tree_inode\n");
		return -1;
	}
		
	if (!len)
		return 0;

	newes.es_lblk = lblk;
	newes.es_pblk = pblk;
	newes.es_len = len;
	newes.inode = inode;

	write_lock(&EXT4_I(inode)->i_es_lock);
	err = __cs_insert_extent(tree_inode, &newes);
	write_unlock(&EXT4_I(inode)->i_es_lock);
	
	return err;
}

void cs_print_tree(struct seq_file *s, struct inode *inode)
{
    struct ext4_es_tree *tree;
    struct rb_node *node;

    tree = &EXT4_I(inode)->i_es_tree;
    node = rb_first(&tree->root);
    while (node) {
        struct extent_status *es;
		es = rb_entry(node, struct extent_status, rb_node);
		seq_printf(s, " %llu:%u\n",ext4_es_pblock(es), es->es_len);
		node = rb_next(node);
   }
}

struct extent_status find_es_in_tree(struct inode *inode, ext4_fsblk_t lba, unsigned int *offset){
	struct extent_status newes;
	struct ext4_es_tree *tree = &EXT4_I(inode)->i_es_tree;
	struct rb_node **p = &tree->root.rb_node;
	struct rb_node *parent = NULL;
	struct extent_status *es;
	newes.es_pblk = (lba - PARTTION_START)/8;
	while (*p) {
		parent = *p;
		es = rb_entry(parent, struct extent_status, rb_node);
		if (newes.es_pblk < es->es_pblk) {
			p = &(*p)->rb_left;
		} else if (newes.es_pblk > cs_end(es)) {
			p = &(*p)->rb_right;
		} else {	
			goto find;
		}
	}
	newes.es_len = -1;
	return newes;
find:
	newes.inode = es->inode;
	newes.es_len = (newes.es_pblk - es->es_pblk); 
	//printk("%llu lba %llu\n", es->es_pblk*8 ,lba-PARTTION_START); 
	*offset = ((lba-PARTTION_START)- es->es_pblk*8)%8; 
	return newes;
}
